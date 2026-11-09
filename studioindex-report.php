<?php
/**
 * Plugin Name: StudioIndex — Report RPP via email
 * Description: Riceve il PDF generato dal calcolatore RPP, registra il contatto, lo invia via email e mette a disposizione dell'amministratore l'elenco completo delle richieste, con reCAPTCHA e protezioni antispam.
 * Version:     3.1.0
 * Author:      StudioIndex
 * License:     GPL-2.0-or-later
 *
 * ---------------------------------------------------------------------------
 * INSTALLAZIONE
 *   /wp-content/plugins/studioindex-report/studioindex-report.php  -> attiva
 *   Menu "Lead RPP"              = elenco delle richieste
 *   Menu "Lead RPP > Impostazioni" = chiavi reCAPTCHA e destinatari
 *   Menu "Lead RPP > Email SMTP"   = server di posta, con invio di prova
 *
 * RECAPITO EMAIL
 *   Server, porta, utente e password SMTP si cambiano dal pannello, senza
 *   toccare il codice. Valgono solo per le email di questo plugin.
 *   Servono comunque SPF e DKIM sul dominio del mittente, altrimenti gli
 *   allegati finiscono nello spam.
 *
 * DIFESE ATTIVE
 *   - reCAPTCHA v2 o v3 (opzionale, si attiva dalle impostazioni)
 *   - honeypot, controllo Origin/Referer, user agent obbligatorio
 *   - 10 invii per IP all'ora, 20 al giorno, 5 al giorno per indirizzo email
 *   - RPP e cluster ricalcolati lato server: i dati falsificati sono ignorati
 *   - limiti su lunghezze, intervalli numerici e dimensione del PDF
 *   - riconoscimento della firma %PDF e di %%EOF prima del salvataggio
 *   - PDF non raggiungibili da URL pubblico: solo admin-post.php con nonce
 *     e capability manage_options, con controllo realpath contro i traversal
 *   - nessuna query SQL scritta a mano, solo WP_Query
 *   - nonce e capability su ogni azione di backend, output sempre escapato
 * ---------------------------------------------------------------------------
 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

final class StudioIndex_Report {

	const VERSION  = '3.1.0';
	const NS       = 'studioindex/v1';
	const CPT      = 'sx_lead';
	const CAP      = 'manage_options';
	const OPTION   = 'sx_settings';
	const SMTP_OPTION = 'sx_smtp';

	/* --- limiti anti abuso --- */
	const MAX_PDF_BYTES = 2097152;   // 2 MB
	const RATE_IP_HOUR  = 10;        // max invii per IP in un'ora
	const RATE_IP_DAY   = 20;        // max invii per IP in 24 ore
	const RATE_MAIL_DAY = 5;         // max invii per email in 24 ore

	/* --- limiti sui valori --- */
	const MAX_NOME      = 80;
	const MAX_EMAIL     = 120;
	const MAX_TEL       = 25;
	const MAX_FATTURATO = 1000000000;
	const MAX_ADDETTI   = 2000;

	private static $instance = null;
	private $force_call = false;   // true nella pagina "Richieste di call"
	private $smtp_log   = array(); // traccia del dialogo SMTP (solo invio di prova)
	private $smtp_err   = '';      // ultimo errore di wp_mail (solo invio di prova)

	public static function boot() {
		if ( null === self::$instance ) { self::$instance = new self(); }
		return self::$instance;
	}

	private function __construct() {
		add_action( 'init',                      array( $this, 'register_cpt' ) );
		add_action( 'rest_api_init',             array( $this, 'register_routes' ) );
		add_action( 'admin_menu',                array( $this, 'admin_menu' ) );
		add_action( 'admin_post_sx_lead_pdf',    array( $this, 'handle_pdf_download' ) );
		add_action( 'admin_post_sx_lead_delete', array( $this, 'handle_delete' ) );
		add_action( 'admin_post_sx_lead_export', array( $this, 'handle_export' ) );
		add_action( 'admin_post_sx_lead_called', array( $this, 'handle_mark_called' ) );
		add_action( 'admin_post_sx_save_opts',   array( $this, 'handle_save_settings' ) );
		add_action( 'admin_post_sx_save_smtp',   array( $this, 'handle_save_smtp' ) );
		add_action( 'admin_post_sx_smtp_test',   array( $this, 'handle_smtp_test' ) );
		add_action( 'before_delete_post',       array( $this, 'cleanup_file' ) );
	}

	/* =====================================================================
	   0. IMPOSTAZIONI
	   ===================================================================== */

	public function opts() {
		$d = array(
			'recaptcha'  => 'off',   // off | v2 | v3
			'site_key'   => '',
			'secret_key' => '',
			'score'      => 0.5,     // solo v3
			'notify_on'  => 0,       // 0 = il report va SOLO all'utente
			'notify'     => "studio@aicommercialista.it\simone.brancozzi@gmail.com",
		);
		$o = get_option( self::OPTION, array() );
		return wp_parse_args( is_array( $o ) ? $o : array(), $d );
	}

	private function notify_emails() {
		$raw  = (string) $this->opts()['notify'];
		$list = preg_split( '/[\s,;]+/', $raw );
		$list = array_filter( array_map( 'sanitize_email', (array) $list ), 'is_email' );
		$list = apply_filters( 'studioindex_notify_emails', array_values( array_unique( $list ) ) );
		return $list;
	}

	private function reply_to_email() {
		$all = $this->notify_emails();
		return $all ? $all[0] : get_option( 'admin_email' );
	}

	private function from_email() {
		$host    = preg_replace( '/^www\./i', '', (string) wp_parse_url( home_url(), PHP_URL_HOST ) );
		$default = 'noreply@' . $host;
		// Con l'SMTP attivo il mittente deve essere la casella autenticata,
		// altrimenti il server rifiuta il messaggio o fallisce l'SPF.
		if ( $this->smtp_active() && $this->smtp_from_address() ) {
			$default = $this->smtp_from_address();
		}
		return apply_filters( 'studioindex_from_email', $default );
	}

	private function from_name() {
		$default = 'StudioIndex';
		if ( $this->smtp_active() ) {
			$n = trim( (string) $this->smtp_opts()['from_name'] );
			if ( '' !== $n ) { $default = $n; }
		}
		return apply_filters( 'studioindex_from_name', $default );
	}

	/* =====================================================================
	   1. ENDPOINT REST
	   ===================================================================== */

	public function register_routes() {
		register_rest_route( self::NS, '/report', array(
			'methods'             => WP_REST_Server::CREATABLE,
			'callback'            => array( $this, 'handle_submit' ),
			'permission_callback' => '__return_true',
		) );

		// Solo dati pubblici: serve al blocco per sapere se e come mostrare il reCAPTCHA.
		register_rest_route( self::NS, '/config', array(
			'methods'             => WP_REST_Server::READABLE,
			'callback'            => array( $this, 'handle_config' ),
			'permission_callback' => '__return_true',
		) );

		// Prenotazione della call dal pulsante contenuto nell'email.
		register_rest_route( self::NS, '/call', array(
			'methods'             => WP_REST_Server::READABLE,
			'callback'            => array( $this, 'handle_call_request' ),
			'permission_callback' => '__return_true',
			'args'                => array(
				'id' => array( 'required' => true ),
				't'  => array( 'required' => true ),
			),
		) );

		// Download del proprio report dal link contenuto nell'email.
		// Protetto da una firma HMAC: senza token valido non serve nulla.
		register_rest_route( self::NS, '/download', array(
			'methods'             => WP_REST_Server::READABLE,
			'callback'            => array( $this, 'handle_public_download' ),
			'permission_callback' => '__return_true',
			'args'                => array(
				'id' => array( 'required' => true ),
				't'  => array( 'required' => true ),
			),
		) );
	}

	/** Firma del link "Prenota la call": salt diverso da quello del download. */
	private function call_token( $lead_id ) {
		$file = basename( (string) get_post_meta( $lead_id, '_sx_pdf', true ) );
		return substr( hash_hmac( 'sha256', $lead_id . '|call|' . $file, wp_salt( 'sx_report_call' ) ), 0, 32 );
	}

	private function call_url( $lead_id ) {
		if ( ! $lead_id ) { return ''; }
		return add_query_arg(
			array( 'id' => $lead_id, 't' => $this->call_token( $lead_id ) ),
			rest_url( self::NS . '/call' )
		);
	}

	/**
	 * L'utente ha premuto "Prenota la call" nell'email.
	 * Registra la richiesta e mostra una pagina di conferma.
	 */
	public function handle_call_request( WP_REST_Request $req ) {
		$id = absint( $req->get_param( 'id' ) );
		$t  = sanitize_text_field( (string) $req->get_param( 't' ) );

		if ( ! $id || get_post_type( $id ) !== self::CPT || ! hash_equals( $this->call_token( $id ), $t ) ) {
			$this->render_call_page( false );
		}

		// Idempotente: se ricarica la pagina non duplichiamo la richiesta.
		if ( ! get_post_meta( $id, '_sx_call', true ) ) {
			update_post_meta( $id, '_sx_call', current_time( 'mysql' ) );
			update_post_meta( $id, '_sx_call_stato', 'da_contattare' );
			$this->notify_call_request( $id );
		}

		$this->render_call_page( true, $id );
	}

	/** Avvisa lo studio che c'e' una persona da richiamare. */
	private function notify_call_request( $id ) {
		$to = $this->notify_emails();
		if ( ! $to ) { return; }

		$nome     = (string) get_post_meta( $id, '_sx_nome', true );
		$tel      = (string) get_post_meta( $id, '_sx_telefono', true );
		$telLink  = preg_replace( '/[^\d+]/', '', $tel );
		$email    = (string) get_post_meta( $id, '_sx_email', true );
		$attivita = (string) get_post_meta( $id, '_sx_attivita', true );
		$regione  = (string) get_post_meta( $id, '_sx_regione', true );
		$fatt     = (float) get_post_meta( $id, '_sx_fatturato', true );
		$add      = (string) get_post_meta( $id, '_sx_addetti', true );
		$rpp      = (float) get_post_meta( $id, '_sx_rpp', true );
		$cname    = (string) get_post_meta( $id, '_sx_cluster_n', true );
		$cluster  = (int) get_post_meta( $id, '_sx_cluster', true );
		$colors   = array( '#AE3F2E', '#BC862A', '#2E7A72', '#2C6B4A' );
		$accent   = isset( $colors[ $cluster ] ) ? $colors[ $cluster ] : '#123B3E';

		/* riga della tabella dei dati */
		$row = function ( $etichetta, $valore ) {
			return '<tr>'
				. '<td style="padding:9px 0;width:150px;font-size:13px;color:#59685F;border-bottom:1px solid #E7EBE7;vertical-align:top;">' . $etichetta . '</td>'
				. '<td style="padding:9px 0;font-size:14px;color:#16251F;border-bottom:1px solid #E7EBE7;font-weight:600;">' . $valore . '</td>'
				. '</tr>';
		};

		ob_start(); ?>
<!DOCTYPE html>
<html lang="it">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Richiesta di richiamo</title></head>
<body style="margin:0;padding:0;background:#F4F6F3;">

<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:#F4F6F3;font-size:1px;line-height:1px;">
  <?php echo esc_html( $nome ); ?> chiede di essere richiamato al <?php echo esc_html( $tel ); ?> entro 24 ore.
</div>

<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#F4F6F3;">
  <tr><td align="center" style="padding:26px 12px;">
    <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:600px;max-width:100%;background:#FFFFFF;border-radius:14px;overflow:hidden;">

      <!-- fascia di allerta -->
      <tr>
        <td style="background:#B87A21;padding:13px 32px;font-family:Arial,Helvetica,sans-serif;font-size:13px;font-weight:bold;color:#231A06;letter-spacing:.3px;">
          DA RICHIAMARE ENTRO 24 ORE
        </td>
      </tr>

      <!-- messaggio principale -->
      <tr>
        <td style="padding:30px 32px 0 32px;font-family:Arial,Helvetica,sans-serif;">
          <div style="font-family:Georgia,'Times New Roman',serif;font-size:22px;line-height:1.3;color:#16251F;">
            <?php echo esc_html( $nome ); ?> ha chiesto di essere ricontattato
          </div>
          <p style="margin:14px 0 0;font-size:15px;line-height:1.65;color:#3C4C45;">
            Ha compilato il calcolatore RPP su studioindex.it e, dopo aver ricevuto il report,
            ha premuto <strong>&laquo;Prenota la call&raquo;</strong> nell'email: chiede una telefonata
            per approfondire i risultati della propria analisi e capire come intervenire sullo studio.
          </p>
          <p style="margin:12px 0 0;font-size:15px;line-height:1.65;color:#3C4C45;">
            Di seguito i dati che ha lasciato al momento della richiesta.
          </p>
        </td>
      </tr>

      <!-- telefono in evidenza -->
      <tr>
        <td style="padding:22px 32px 0 32px;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
                 style="background:#F4F6F3;border:1px solid #DCE3DC;border-radius:10px;">
            <tr>
              <td style="padding:20px 24px;font-family:Arial,Helvetica,sans-serif;">
                <div style="font-size:11px;letter-spacing:.6px;text-transform:uppercase;color:#59685F;">Da chiamare al numero</div>
                <div style="padding-top:6px;">
                  <a href="tel:<?php echo esc_attr( $telLink ); ?>"
                     style="font-family:Georgia,'Times New Roman',serif;font-size:27px;font-weight:bold;color:#123B3E;text-decoration:none;">
                    <?php echo esc_html( $tel ); ?>
                  </a>
                </div>
                <div style="padding-top:8px;font-size:13px;color:#59685F;">
                  Richiesta ricevuta il <?php echo esc_html( current_time( 'd/m/Y' ) ); ?>
                  alle <?php echo esc_html( current_time( 'H:i' ) ); ?>
                </div>
              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- dati dell'applicante -->
      <tr>
        <td style="padding:26px 32px 0 32px;font-family:Arial,Helvetica,sans-serif;">
          <div style="font-size:11px;letter-spacing:.6px;text-transform:uppercase;color:#123B3E;font-weight:bold;padding-bottom:4px;">
            Dati dell'applicante
          </div>
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
			<?php
			echo $row( 'Nome e cognome', esc_html( $nome ) );
			echo $row( 'Telefono', '<a href="tel:' . esc_attr( $telLink ) . '" style="color:#123B3E;">' . esc_html( $tel ) . '</a>' );
			echo $row( 'Email', '<a href="mailto:' . esc_attr( $email ) . '" style="color:#123B3E;">' . esc_html( $email ) . '</a>' );
			echo $row( 'Attivit&agrave;', esc_html( $attivita ) );
			echo $row( 'Regione', esc_html( $regione ) );
			echo $row( 'Fatturato dichiarato', '&euro; ' . esc_html( number_format( $fatt, 0, ',', '.' ) ) );
			echo $row( 'Addetti (FTE)', esc_html( str_replace( '.', ',', $add ) ) );
			echo $row( 'RPP calcolato', '&euro; ' . esc_html( number_format( $rpp, 0, ',', '.' ) ) . ' per addetto' );
			echo $row( 'Tipologia di studio',
				'<span style="display:inline-block;background:' . esc_attr( $accent ) . ';color:#FFFFFF;font-size:12px;padding:3px 11px;border-radius:12px;">'
				. esc_html( $cname ) . '</span>' );
			?>
          </table>
        </td>
      </tr>

      <!-- azione -->
      <tr>
        <td style="padding:24px 32px 0 32px;" align="center">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center">
            <tr>
              <td align="center" style="background:#123B3E;border-radius:8px;">
                <a href="<?php echo esc_url( admin_url( 'admin.php?page=sx-calls' ) ); ?>"
                   style="display:inline-block;padding:13px 26px;font-family:Arial,Helvetica,sans-serif;font-size:14.5px;font-weight:bold;color:#FFFFFF;text-decoration:none;border-radius:8px;">
                  Apri l'elenco delle call
                </a>
              </td>
            </tr>
          </table>
          <div style="padding-top:12px;font-family:Arial,Helvetica,sans-serif;font-size:12.5px;color:#8A978F;">
            Dopo la telefonata segna il contatto come <strong>&laquo;Contattato&raquo;</strong>,
            cos&igrave; nessuno lo richiama due volte.
          </div>
        </td>
      </tr>

      <!-- piede -->
      <tr>
        <td style="padding:26px 32px 26px 32px;font-family:Arial,Helvetica,sans-serif;">
          <div style="border-top:1px solid #E7EBE7;padding-top:16px;font-size:12px;line-height:1.6;color:#8A978F;">
            Messaggio automatico del calcolatore RPP di StudioIndex.
            Il report in PDF inviato all'applicante &egrave; consultabile dal pannello, nella riga corrispondente.
          </div>
        </td>
      </tr>

    </table>
  </td></tr>
</table>
</body>
</html>
		<?php
		$body = ob_get_clean();

		$this->mail_hooks_on();

		wp_mail(
			$to,
			sprintf( 'Da richiamare: %s — %s', $nome, $tel ),
			$body,
			array( 'Reply-To: ' . $this->header_safe( $nome ) . ' <' . $email . '>' )
		);

		$this->mail_hooks_off();
	}

	/** Pagina mostrata dopo il clic sul pulsante dell'email. */
	private function render_call_page( $ok, $id = 0 ) {
		$tel = $id ? (string) get_post_meta( $id, '_sx_telefono', true ) : '';
		nocache_headers();
		header( 'Content-Type: text/html; charset=utf-8' );
		header( 'X-Robots-Tag: noindex, nofollow' );
		?><!DOCTYPE html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title><?php echo $ok ? 'Call prenotata' : 'Link non valido'; ?> — StudioIndex</title>
<style>
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
       background:#F4F6F3;color:#16251F;padding:24px;
       font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;line-height:1.55}
  .card{background:#fff;border:1px solid #DCE3DC;border-radius:18px;max-width:520px;width:100%;
        padding:44px 38px;text-align:center;box-shadow:0 30px 70px -40px rgba(18,59,62,.45)}
  .tick{width:66px;height:66px;border-radius:50%;background:<?php echo $ok ? '#123B3E' : '#AE3F2E'; ?>;
        margin:0 auto 22px;position:relative}
  .tick::after{content:"";position:absolute;<?php echo $ok
      ? 'left:24px;top:16px;width:13px;height:27px;border:solid #fff;border-width:0 3px 3px 0;transform:rotate(43deg)'
      : 'left:32px;top:18px;width:2px;height:30px;background:#fff;box-shadow:0 0 0 0 #fff'; ?>}
  h1{font-family:Georgia,'Times New Roman',serif;font-size:27px;font-weight:600;line-height:1.25;margin:0 0 14px}
  p{margin:0 0 14px;font-size:16px;color:#3C4C45}
  .tel{display:inline-block;margin-top:6px;font-size:14px;color:#59685F}
  .brand{margin-top:30px;padding-top:22px;border-top:1px solid #DCE3DC;font-size:13px;color:#59685F}
  .brand b{font-family:Georgia,serif;color:#16251F}
  a{color:#123B3E}
</style>
</head>
<body>
  <div class="card">
    <div class="tick"></div>
	<?php if ( $ok ) : ?>
    <h1>Grazie di aver prenotato una call</h1>
    <p>Sarai ricontattato entro 24 ore.</p>
		<?php if ( $tel ) : ?>
    <div class="tel">Ti chiameremo al numero <strong><?php echo esc_html( $tel ); ?></strong></div>
		<?php endif; ?>
	<?php else : ?>
    <h1>Link non valido</h1>
    <p>Il collegamento non &egrave; corretto oppure non &egrave; piu&#39; attivo.
       Scrivici a <a href="mailto:studio@aicommercialista.it">studio@aicommercialista.it</a>
       chiama il N&deg; verde 800-911-393 o scrivici su WhatsApp al 0734 605020.</p>
	<?php endif; ?>
    <div class="brand"><b>StudioIndex</b><br>AI Commercialista srl &middot; N&deg; verde 800-911-393 &middot; WhatsApp 0734 605020</div>
  </div>
</body>
</html>
		<?php
		exit;
	}

	/** Firma non indovinabile, legata al singolo lead e al suo file. */
	private function download_token( $lead_id ) {
		$file = basename( (string) get_post_meta( $lead_id, '_sx_pdf', true ) );
		return substr( hash_hmac( 'sha256', $lead_id . '|' . $file, wp_salt( 'sx_report_dl' ) ), 0, 32 );
	}

	private function download_url( $lead_id ) {
		if ( ! $lead_id ) { return ''; }
		return add_query_arg(
			array( 'id' => $lead_id, 't' => $this->download_token( $lead_id ) ),
			rest_url( self::NS . '/download' )
		);
	}

	public function handle_public_download( WP_REST_Request $req ) {
		$id = absint( $req->get_param( 'id' ) );
		$t  = sanitize_text_field( (string) $req->get_param( 't' ) );

		if ( ! $id || get_post_type( $id ) !== self::CPT ) {
			return $this->fail( 'Report non trovato.', 404 );
		}
		// hash_equals evita gli attacchi a tempo sul confronto della firma
		if ( ! hash_equals( $this->download_token( $id ), $t ) ) {
			return $this->fail( 'Link non valido o scaduto.', 403 );
		}

		$real = $this->safe_pdf_path( $id );
		if ( ! $real ) {
			return $this->fail( 'Il file non e\' piu\' disponibile.', 404 );
		}

		nocache_headers();
		header( 'Content-Type: application/pdf' );
		header( 'Content-Disposition: attachment; filename="report-rpp-studioindex.pdf"' );
		header( 'Content-Length: ' . filesize( $real ) );
		header( 'X-Content-Type-Options: nosniff' );
		header( 'X-Robots-Tag: noindex, nofollow' );
		readfile( $real );
		exit;
	}

	public function handle_config() {
		$o = $this->opts();
		$on = in_array( $o['recaptcha'], array( 'v2', 'v3' ), true ) && '' !== trim( $o['site_key'] ) && '' !== trim( $o['secret_key'] );
		return new WP_REST_Response( array(
			'recaptcha' => $on ? $o['recaptcha'] : 'off',
			'site_key'  => $on ? $o['site_key'] : '',
		), 200 );
	}

	public function handle_submit( WP_REST_Request $req ) {

		/* ---------- 1.1 filtri antispam ---------- */
		if ( '' !== trim( (string) $req->get_param( 'website' ) ) ) {
			return $this->fail( 'Richiesta non valida.', 400 );
		}
		if ( ! $this->same_origin( $req ) ) {
			return $this->fail( 'Origine della richiesta non riconosciuta.', 403 );
		}
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 255 ) : '';
		if ( '' === $ua ) {
			return $this->fail( 'Richiesta non valida.', 400 );
		}

		$ip = $this->ip();
		if ( ! $this->rate_check( 'h_' . $ip, self::RATE_IP_HOUR, HOUR_IN_SECONDS ) ) {
			return $this->fail( sprintf(
				'Hai gia\' richiesto il report %d volte in un\'ora. Riprova piu\' tardi o scrivici a %s.',
				self::RATE_IP_HOUR, $this->reply_to_email()
			), 429 );
		}
		if ( ! $this->rate_check( 'd_' . $ip, self::RATE_IP_DAY, DAY_IN_SECONDS ) ) {
			return $this->fail( 'Hai raggiunto il numero massimo di richieste giornaliere da questo collegamento.', 429 );
		}

		/* ---------- 1.2 reCAPTCHA ---------- */
		$rc = $this->verify_recaptcha( (string) $req->get_param( 'recaptcha' ), $ip );
		if ( is_wp_error( $rc ) ) {
			return $this->fail( $rc->get_error_message(), 403 );
		}

		/* ---------- 1.3 validazione ---------- */
		$nome = trim( preg_replace( '/\s+/u', ' ', sanitize_text_field( (string) $req->get_param( 'nome' ) ) ) );
		if ( mb_strlen( $nome ) < 2 || mb_strlen( $nome ) > self::MAX_NOME ) {
			return $this->fail( 'Nome non valido.', 400 );
		}
		if ( preg_match( '~(https?://|www\.|\[url)~i', $nome ) ) {
			return $this->fail( 'Nome non valido.', 400 );
		}

		$email = sanitize_email( (string) $req->get_param( 'email' ) );
		if ( ! is_email( $email ) || strlen( $email ) > self::MAX_EMAIL ) {
			return $this->fail( 'Email non valida.', 400 );
		}
		if ( ! $this->rate_check( 'm_' . md5( strtolower( $email ) ), self::RATE_MAIL_DAY, DAY_IN_SECONDS ) ) {
			return $this->fail( sprintf(
				'Per questo indirizzo email sono gia\' stati inviati %d report nelle ultime 24 ore.',
				self::RATE_MAIL_DAY
			), 429 );
		}

		$telefono = sanitize_text_field( (string) $req->get_param( 'telefono' ) );
		$telefono = trim( preg_replace( '/[^\d+\-()\s.]/', '', $telefono ) );
		if ( strlen( $telefono ) > self::MAX_TEL || strlen( preg_replace( '/\D/', '', $telefono ) ) < 6 ) {
			return $this->fail( 'Numero di telefono non valido.', 400 );
		}

		$regione = sanitize_text_field( (string) $req->get_param( 'regione' ) );
		if ( ! in_array( $regione, self::regioni(), true ) ) {
			return $this->fail( 'Regione non valida.', 400 );
		}

		$attivita = sanitize_text_field( (string) $req->get_param( 'attivita' ) );
		if ( ! in_array( $attivita, self::attivita(), true ) ) {
			return $this->fail( 'Attivita\' non valida.', 400 );
		}

		if ( ! (bool) $req->get_param( 'consenso' ) ) {
			return $this->fail( 'Consenso al trattamento dei dati mancante.', 400 );
		}

		$fatturato = (int) round( (float) $req->get_param( 'fatturato' ) );
		$addetti   = round( (float) $req->get_param( 'addetti' ), 1 );
		if ( $fatturato < 1 || $fatturato > self::MAX_FATTURATO ) {
			return $this->fail( 'Fatturato fuori intervallo.', 400 );
		}
		if ( $addetti < 0.1 || $addetti > self::MAX_ADDETTI ) {
			return $this->fail( 'Numero di addetti fuori intervallo.', 400 );
		}

		/* ---------- 1.4 ricalcolo lato server ---------- */
		$rpp     = (int) round( $fatturato / $addetti );
		$cluster = $this->classify( $rpp );
		$cname   = $this->cluster_name( $cluster );

		/* ---------- 1.5 PDF ---------- */
		$b64 = preg_replace( '/\s+/', '', (string) $req->get_param( 'pdf' ) );
		if ( '' === $b64 || ! preg_match( '~^[A-Za-z0-9+/]+={0,2}$~', $b64 ) ) {
			return $this->fail( 'Allegato mancante o corrotto.', 400 );
		}
		if ( strlen( $b64 ) > (int) ( self::MAX_PDF_BYTES * 1.4 ) ) {
			return $this->fail( 'Allegato troppo grande.', 413 );
		}
		$bin = base64_decode( $b64, true );
		unset( $b64 );
		if ( false === $bin
			|| strlen( $bin ) < 500
			|| strlen( $bin ) > self::MAX_PDF_BYTES
			|| 0 !== strncmp( $bin, '%PDF-', 5 )
			|| false === strpos( substr( $bin, -2048 ), '%%EOF' ) ) {
			return $this->fail( 'Il file generato non e\' un PDF valido.', 400 );
		}

		$path = $this->store_pdf( $bin, $nome );
		unset( $bin );
		if ( is_wp_error( $path ) ) {
			return $this->fail( 'Non e\' stato possibile salvare il report.', 500 );
		}

		/* ---------- 1.6 registrazione ---------- */
		$lead_id = wp_insert_post( array(
			'post_type'   => self::CPT,
			'post_status' => 'publish',
			'post_title'  => $nome . ' — ' . $email . ' — ' . $telefono,
		), true );

		if ( is_wp_error( $lead_id ) ) {
			$lead_id = 0;
		} else {
			$meta = array(
				'_sx_nome'      => $nome,
				'_sx_email'     => $email,
				'_sx_telefono'  => $telefono,
				'_sx_attivita'  => $attivita,
				'_sx_regione'   => $regione,
				'_sx_fatturato' => $fatturato,
				'_sx_addetti'   => $addetti,
				'_sx_rpp'       => $rpp,
				'_sx_cluster'   => $cluster,
				'_sx_cluster_n' => $cname,
				'_sx_pdf'       => $path,
				'_sx_ip'        => $ip,
				'_sx_ua'        => $ua,
				'_sx_consenso'  => current_time( 'mysql' ),
			);
			foreach ( $meta as $k => $v ) { update_post_meta( $lead_id, $k, $v ); }
		}

		/* ---------- 1.7 email ---------- */
		$this->mail_hooks_on();

		$data = compact( 'nome', 'email', 'telefono', 'attivita', 'regione', 'fatturato', 'addetti', 'rpp', 'cname', 'ip' );

		$sent_user = wp_mail(
			$email,
			'Il tuo report RPP — StudioIndex',
			$this->mail_user( $nome, $rpp, $cname, $cluster, $this->download_url( $lead_id ), $this->call_url( $lead_id ) ),
			array( 'Reply-To: ' . $this->reply_to_email() ),
			array( $path )
		);

		/* Copia interna: inviata solo se attivata nelle impostazioni.
		   Di default il report arriva SOLO all'utente; la richiesta resta
		   comunque registrata nel menu "Lead RPP". */
		$recipients = $this->notify_emails();
		if ( $this->opts()['notify_on'] && $recipients ) {
			wp_mail(
				$recipients,
				sprintf( '[Lead RPP] %s — %s €/addetto (%s)', $nome, number_format( $rpp, 0, ',', '.' ), $cname ),
				$this->mail_studio( $data, $lead_id ),
				array( 'Reply-To: ' . $this->header_safe( $nome ) . ' <' . $email . '>' ),
				array( $path )
			);
		}

		$this->mail_hooks_off();

		if ( $lead_id ) { update_post_meta( $lead_id, '_sx_sent', $sent_user ? 1 : 0 ); }

		if ( ! $sent_user ) {
			return $this->fail( 'Il report e\' stato creato ma l\'invio dell\'email non e\' riuscito. Ti ricontattiamo noi.', 500 );
		}

		return new WP_REST_Response( array( 'success' => true, 'message' => 'Report inviato.' ), 200 );
	}

	/* =====================================================================
	   2. SICUREZZA
	   ===================================================================== */

	/** Verifica il token reCAPTCHA presso Google. */
	private function verify_recaptcha( $token, $ip ) {
		$o = $this->opts();
		if ( ! in_array( $o['recaptcha'], array( 'v2', 'v3' ), true ) ) { return true; }
		if ( '' === trim( $o['secret_key'] ) )                          { return true; }

		$token = trim( $token );
		if ( '' === $token || strlen( $token ) > 4096 ) {
			return new WP_Error( 'captcha', 'Verifica antispam non superata. Ricarica la pagina e riprova.' );
		}

		$res = wp_remote_post( 'https://www.google.com/recaptcha/api/siteverify', array(
			'timeout' => 10,
			'body'    => array(
				'secret'   => $o['secret_key'],
				'response' => $token,
				'remoteip' => $ip,
			),
		) );

		if ( is_wp_error( $res ) ) {
			// Google irraggiungibile: non blocchiamo un utente legittimo.
			return true;
		}

		$body = json_decode( wp_remote_retrieve_body( $res ), true );
		if ( ! is_array( $body ) || empty( $body['success'] ) ) {
			return new WP_Error( 'captcha', 'Verifica antispam non superata. Riprova.' );
		}

		if ( 'v3' === $o['recaptcha'] ) {
			$score = isset( $body['score'] ) ? (float) $body['score'] : 0;
			$min   = (float) $o['score'];
			if ( $score < $min ) {
				return new WP_Error( 'captcha', 'La richiesta e\' stata segnalata come automatica. Se sei una persona, scrivici a ' . $this->reply_to_email() . '.' );
			}
			if ( isset( $body['action'] ) && 'rpp_report' !== $body['action'] ) {
				return new WP_Error( 'captcha', 'Verifica antispam non valida.' );
			}
		}
		return true;
	}

	private function same_origin( WP_REST_Request $req ) {
		$host   = wp_parse_url( home_url(), PHP_URL_HOST );
		$origin = $req->get_header( 'origin' );

		if ( $origin ) {
			return 0 === strcasecmp( (string) wp_parse_url( $origin, PHP_URL_HOST ), (string) $host );
		}
		$ref = wp_get_referer();
		if ( ! $ref && isset( $_SERVER['HTTP_REFERER'] ) ) {
			$ref = esc_url_raw( wp_unslash( $_SERVER['HTTP_REFERER'] ) );
		}
		if ( $ref ) {
			return 0 === strcasecmp( (string) wp_parse_url( $ref, PHP_URL_HOST ), (string) $host );
		}
		return false;
	}

	private function ip() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? wp_unslash( $_SERVER['REMOTE_ADDR'] ) : '';
		if ( apply_filters( 'studioindex_trust_proxy', false ) && isset( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
			$ip = wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] );
		}
		$ip = filter_var( $ip, FILTER_VALIDATE_IP );
		return $ip ? $ip : '0.0.0.0';
	}

	private function rate_check( $suffix, $max, $window ) {
		$key = 'sx_rl_' . md5( $suffix . '|' . $window );
		$n   = (int) get_transient( $key );
		if ( $n >= $max ) { return false; }
		set_transient( $key, $n + 1, $window );
		return true;
	}

	private function header_safe( $s ) {
		return trim( str_replace( array( "\r", "\n", '<', '>', ',', ';', '"' ), ' ', (string) $s ) );
	}

	private function classify( $rpp ) {
		if ( $rpp < 35000 )  { return 0; }
		if ( $rpp < 60000 )  { return 1; }
		if ( $rpp < 130000 ) { return 2; }
		return 3;
	}

	public function cluster_name( $i ) {
		$n = array( 'The Zombie Practice', 'Traditional Commodity Trap', 'Functional Practice', 'Scalable Asset Practice' );
		return isset( $n[ $i ] ) ? $n[ $i ] : '—';
	}

	/** Elenchi chiusi: qualsiasi altro valore viene rifiutato. */
	public static function regioni() {
		return array(
			'Abruzzo', 'Basilicata', 'Calabria', 'Campania', 'Emilia-Romagna',
			'Friuli-Venezia Giulia', 'Lazio', 'Liguria', 'Lombardia', 'Marche',
			'Molise', 'Piemonte', 'Puglia', 'Sardegna', 'Sicilia', 'Toscana',
			'Trentino-Alto Adige', 'Umbria', "Valle d'Aosta", 'Veneto',
		);
	}

	public static function attivita() {
		return array(
			'Dottore commercialista', 'Esperto contabile', 'Consulente del lavoro',
			'Revisore legale', 'Studio associato / STP', 'Avvocato tributarista',
			'Centro elaborazione dati (CED)', 'Consulente aziendale', 'Consulente',
			'Imprenditore', 'Dirigente', 'Impiegato', 'Altro',
		);
	}

	private function fail( $msg, $code ) {
		return new WP_REST_Response( array( 'success' => false, 'message' => $msg ), $code );
	}

	/* =====================================================================
	   3. EMAIL
	   ===================================================================== */

	public function f_from()      { return $this->from_email(); }
	public function f_from_name() { return $this->from_name(); }
	public function f_html()      { return 'text/html'; }

	/**
	 * Email inviata all'utente.
	 * Impaginazione a tabelle e stili inline: e' l'unico modo affidabile
	 * perche' Outlook, Gmail e Apple Mail rendano lo stesso risultato.
	 */
	private function mail_user( $nome, $rpp, $cname, $cluster = 2, $dl = '', $call = '' ) {
		$colors = array( '#AE3F2E', '#BC862A', '#2E7A72', '#2C6B4A' );
		$accent = isset( $colors[ $cluster ] ) ? $colors[ $cluster ] : '#123B3E';
		$primo  = explode( ' ', trim( $nome ) );
		$primo  = $primo[0];
		ob_start(); ?>
<!DOCTYPE html>
<html lang="it">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Report RPP</title></head>
<body style="margin:0;padding:0;background:#F4F6F3;">

<!-- testo di anteprima nella casella di posta, non visibile nel messaggio -->
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:#F4F6F3;font-size:1px;line-height:1px;">
  In allegato il report RPP del Suo studio, con il posizionamento tra le quattro tipologie di studio professionale.
</div>

<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#F4F6F3;">
  <tr><td align="center" style="padding:28px 12px;">

    <table role="presentation" width="600" cellpadding="0" cellspacing="0" border="0" style="width:600px;max-width:100%;background:#FFFFFF;border-radius:14px;overflow:hidden;box-shadow:0 2px 10px rgba(18,59,62,.08);">

      <!-- INTESTAZIONE -->
      <tr>
        <td style="background:#123B3E;padding:26px 34px;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
            <tr>
              <td style="font-family:Georgia,'Times New Roman',serif;font-size:21px;font-weight:bold;color:#FFFFFF;letter-spacing:-.2px;">
                StudioIndex
              </td>
              <td align="right" style="font-family:Arial,Helvetica,sans-serif;font-size:11px;color:#9FC0BC;">
                <?php echo esc_html( current_time( 'd/m/Y' ) ); ?>
              </td>
            </tr>
            <tr>
              <td colspan="2" style="padding-top:5px;font-family:Arial,Helvetica,sans-serif;font-size:11.5px;color:#9FC0BC;">
                Indice indipendente di produttivit&agrave; per gli studi professionali
              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- SALUTO -->
      <tr>
        <td style="padding:34px 34px 0 34px;font-family:Arial,Helvetica,sans-serif;">
          <div style="font-family:Georgia,'Times New Roman',serif;font-size:25px;line-height:1.25;color:#16251F;">
            Grazie, <?php echo esc_html( $primo ); ?>
          </div>
          <p style="margin:14px 0 0;font-size:15px;line-height:1.65;color:#3C4C45;">
            La ringraziamo per aver utilizzato il calcolatore RPP. In allegato trover&agrave; il report
            completo in formato PDF, con l'analisi del Suo studio e il posizionamento rispetto alle
            quattro tipologie di studio professionale.
          </p>
        </td>
      </tr>

      <!-- RISULTATO -->
      <tr>
        <td style="padding:24px 34px 0 34px;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
                 style="background:#F4F6F3;border:1px solid #DCE3DC;border-left:4px solid <?php echo esc_attr( $accent ); ?>;border-radius:10px;">
            <tr>
              <td style="padding:22px 26px;font-family:Arial,Helvetica,sans-serif;">
                <div style="font-size:11px;letter-spacing:.6px;text-transform:uppercase;color:#59685F;">
                  Il Suo indice
                </div>
                <div style="font-family:Georgia,'Times New Roman',serif;font-size:36px;font-weight:bold;color:#16251F;padding:6px 0 2px;">
                  &euro; <?php echo esc_html( number_format( $rpp, 0, ',', '.' ) ); ?>
                </div>
                <div style="font-size:13px;color:#59685F;">ricavo per addetto</div>
                <div style="padding-top:12px;">
                  <span style="display:inline-block;background:<?php echo esc_attr( $accent ); ?>;color:#FFFFFF;font-size:12px;font-weight:bold;padding:5px 13px;border-radius:14px;">
                    <?php echo esc_html( $cname ); ?>
                  </span>
                </div>
              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- CONTENUTO DEL REPORT -->
      <tr>
        <td style="padding:24px 34px 0 34px;font-family:Arial,Helvetica,sans-serif;">
          <p style="margin:0;font-size:15px;line-height:1.65;color:#3C4C45;">
            All'interno del documento trover&agrave; che cosa significa questo valore per il Suo studio,
            i tratti tipici della fascia in cui si colloca e il percorso di sviluppo che proponiamo.
          </p>
        </td>
      </tr>

      <!-- INVITO ALLA CALL -->
      <tr>
        <td style="padding:28px 34px 0 34px;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
                 style="background:#123B3E;border-radius:12px;">
            <tr>
              <td style="padding:30px 30px 26px 30px;font-family:Arial,Helvetica,sans-serif;text-align:center;">

                <div style="font-family:Georgia,'Times New Roman',serif;font-size:22px;color:#FFFFFF;line-height:1.3;">
                  Prenota la call di audit
                </div>

                <p style="margin:12px auto 0;max-width:420px;font-size:14.5px;line-height:1.6;color:#CFE0DD;">
                  Progettiamo insieme il salto verso lo studio scalabile, sul tuo caso reale.
                  Gratuita e senza impegno.
                </p>

                <!-- pulsante -->
                <table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center" style="margin:22px auto 0;">
                  <tr>
                    <td align="center" style="background:#B87A21;border-radius:8px;">
                      <a href="<?php echo esc_url( $call ? $call : 'mailto:studio@aicommercialista.it?subject=Richiesta%20call%20di%20audit%20RPP' ); ?>"
                         style="display:inline-block;padding:14px 30px;font-family:Arial,Helvetica,sans-serif;font-size:15px;font-weight:bold;color:#231A06;text-decoration:none;border-radius:8px;">
                        Prenota la call
                      </a>
                    </td>
                  </tr>
                </table>

                <div style="padding-top:10px;font-size:12px;color:#9FC0BC;">
                  Un clic &egrave; sufficiente: la richiameremo entro 24 ore.
                </div>

                <!-- recapiti -->
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin-top:22px;">
                  <tr><td style="border-top:1px solid rgba(255,255,255,.18);font-size:0;line-height:0;">&nbsp;</td></tr>
                </table>
                <div style="padding-top:16px;font-size:13.5px;line-height:1.7;color:#E9DCC4;">
                  <a href="mailto:studio@aicommercialista.it" style="color:#E9DCC4;text-decoration:none;">studio@aicommercialista.it</a>
                  <span style="color:#5C807C;">&nbsp;&middot;&nbsp;</span>
                  <a href="tel:800911393" style="color:#E9DCC4;text-decoration:none;">N&deg; verde 800-911-393</a>
                  <span style="color:#5C807C;">&nbsp;&middot;&nbsp;</span>
                  <a href="https://wa.me/390734605020" style="color:#E9DCC4;text-decoration:none;">WhatsApp 0734 605020</a>
                </div>

              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- SCARICA IL REPORT -->
      <tr>
        <td style="padding:28px 34px 0 34px;">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
                 style="border:1px solid #DCE3DC;border-radius:12px;background:#FFFFFF;">
            <tr>
              <td style="padding:24px 26px;font-family:Arial,Helvetica,sans-serif;text-align:center;">

                <div style="font-size:11px;letter-spacing:.6px;text-transform:uppercase;color:#59685F;">
                  Il Suo documento
                </div>
                <div style="font-family:Georgia,'Times New Roman',serif;font-size:18px;color:#16251F;padding:6px 0 0;">
                  Report RPP &mdash; <?php echo esc_html( $cname ); ?>
                </div>
                <div style="font-size:13px;color:#59685F;padding-top:5px;">
                  PDF, 1 pagina &middot; formato A4, pronto per la stampa
                </div>

				<?php if ( $dl ) : ?>
                <table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center" style="margin:18px auto 0;">
                  <tr>
                    <td align="center" style="background:#123B3E;border-radius:8px;">
                      <a href="<?php echo esc_url( $dl ); ?>"
                         style="display:inline-block;padding:13px 28px;font-family:Arial,Helvetica,sans-serif;font-size:15px;font-weight:bold;color:#FFFFFF;text-decoration:none;border-radius:8px;">
                        Scarica il report in PDF
                      </a>
                    </td>
                  </tr>
                </table>
                <div style="padding-top:12px;font-size:12px;color:#8A978F;">
                  Il documento &egrave; allegato a questo messaggio; il pulsante serve
                  se il Suo programma di posta non mostra gli allegati.
                </div>
				<?php else : ?>
                <div style="padding-top:12px;font-size:12px;color:#8A978F;">
                  Il documento &egrave; allegato a questo messaggio.
                </div>
				<?php endif; ?>

              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- CHIUSURA -->
      <tr>
        <td style="padding:28px 34px 34px 34px;font-family:Arial,Helvetica,sans-serif;">
          <p style="margin:0;font-size:15px;line-height:1.65;color:#3C4C45;">
            Per qualsiasi chiarimento sul report pu&ograve; rispondere direttamente a questo messaggio.
          </p>
          <p style="margin:18px 0 0;font-size:15px;line-height:1.65;color:#3C4C45;">
            Cordiali saluti,<br>
            <strong style="color:#16251F;">Il team StudioIndex</strong>
          </p>
        </td>
      </tr>

      <!-- PIEDE -->
      <tr>
        <td style="background:#0C2A2C;padding:22px 34px;font-family:Arial,Helvetica,sans-serif;">
          <div style="font-size:12px;line-height:1.6;color:#9FB8B4;">
            <strong style="color:#FFFFFF;">AI Commercialista srl</strong> &middot; P.IVA IT14379930960<br>
            Sede legale: Via Cusani 10, 20121 Milano (MI)<br>
            Sede operativa: C.da Campiglione 20, 63900 Fermo (FM)
          </div>
          <div style="padding-top:12px;font-size:11px;line-height:1.6;color:#6F8F8B;">
            Riceve questo messaggio perch&eacute; ha richiesto il report RPP su studioindex.it.
            I riferimenti di fascia hanno valore orientativo e non sostituiscono una valutazione
            professionale del singolo studio.
            <a href="https://studioindex.it/privacy/" style="color:#9FB8B4;">Privacy policy</a>
          </div>
        </td>
      </tr>

    </table>

  </td></tr>
</table>
</body>
</html>
		<?php return ob_get_clean();
	}

	private function mail_studio( $d, $lead_id ) {
		$link = admin_url( 'admin.php?page=sx-leads' );
		ob_start(); ?>
<div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.6;color:#16251F">
  <p><strong>Nuova richiesta dal calcolatore RPP</strong></p>
  <table cellpadding="6" cellspacing="0" border="0">
    <tr><td><strong>Nome</strong></td><td><?php echo esc_html( $d['nome'] ); ?></td></tr>
    <tr><td><strong>Email</strong></td><td><a href="mailto:<?php echo esc_attr( $d['email'] ); ?>"><?php echo esc_html( $d['email'] ); ?></a></td></tr>
    <tr><td><strong>Telefono</strong></td><td><a href="tel:<?php echo esc_attr( preg_replace( '/[^\d+]/', '', $d['telefono'] ) ); ?>"><?php echo esc_html( $d['telefono'] ); ?></a></td></tr>
    <tr><td><strong>Attivit&agrave;</strong></td><td><?php echo esc_html( $d['attivita'] ); ?></td></tr>
    <tr><td><strong>Regione</strong></td><td><?php echo esc_html( $d['regione'] ); ?></td></tr>
    <tr><td><strong>Fatturato</strong></td><td>&euro; <?php echo esc_html( number_format( $d['fatturato'], 0, ',', '.' ) ); ?></td></tr>
    <tr><td><strong>Addetti</strong></td><td><?php echo esc_html( str_replace( '.', ',', (string) $d['addetti'] ) ); ?></td></tr>
    <tr><td><strong>RPP</strong></td><td>&euro; <?php echo esc_html( number_format( $d['rpp'], 0, ',', '.' ) ); ?></td></tr>
    <tr><td><strong>Cluster</strong></td><td><?php echo esc_html( $d['cname'] ); ?></td></tr>
    <tr><td><strong>Data e ora</strong></td><td><?php echo esc_html( current_time( 'd/m/Y H:i' ) ); ?></td></tr>
    <tr><td><strong>IP</strong></td><td><?php echo esc_html( $d['ip'] ); ?></td></tr>
  </table>
  <p><a href="<?php echo esc_url( $link ); ?>">Apri l'elenco delle richieste</a></p>
  <p style="color:#59685F">Il PDF inviato al contatto e' in allegato.</p>
</div>
		<?php return ob_get_clean();
	}

	/* =====================================================================
	   4. ARCHIVIO PDF
	   ===================================================================== */

	private function store_pdf( $bin, $nome ) {
		$up = wp_upload_dir();
		if ( ! empty( $up['error'] ) ) { return new WP_Error( 'upload_dir', $up['error'] ); }

		$dir = trailingslashit( $up['basedir'] ) . 'studioindex-reports';
		if ( ! file_exists( $dir ) && ! wp_mkdir_p( $dir ) ) {
			return new WP_Error( 'mkdir', 'Cartella non creata' );
		}
		if ( ! file_exists( $dir . '/.htaccess' ) ) {
			file_put_contents( $dir . '/.htaccess', "Options -Indexes\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n" );
		}
		if ( ! file_exists( $dir . '/index.php' ) ) {
			file_put_contents( $dir . '/index.php', "<?php // silence is golden\n" );
		}

		$slug = sanitize_file_name( sanitize_title( $nome ) );
		$slug = $slug ? substr( $slug, 0, 40 ) : 'lead';
		$file = $dir . '/' . $slug . '-' . gmdate( 'Ymd-His' ) . '-' . wp_generate_password( 16, false, false ) . '.pdf';

		if ( false === file_put_contents( $file, $bin ) ) {
			return new WP_Error( 'write', 'Scrittura fallita' );
		}
		@chmod( $file, 0640 );
		return $file;
	}

	private function safe_pdf_path( $lead_id ) {
		$path = (string) get_post_meta( $lead_id, '_sx_pdf', true );
		if ( ! $path || ! file_exists( $path ) ) { return false; }

		$up   = wp_upload_dir();
		$base = realpath( trailingslashit( $up['basedir'] ) . 'studioindex-reports' );
		$real = realpath( $path );

		if ( ! $base || ! $real || 0 !== strpos( $real, $base . DIRECTORY_SEPARATOR ) ) { return false; }
		return $real;
	}

	public function cleanup_file( $post_id ) {
		if ( get_post_type( $post_id ) !== self::CPT ) { return; }
		$real = $this->safe_pdf_path( $post_id );
		if ( $real ) { @unlink( $real ); }
	}

	/* =====================================================================
	   5. TIPO DI CONTENUTO
	   ===================================================================== */

	public function register_cpt() {
		register_post_type( self::CPT, array(
			'labels'              => array( 'name' => 'Lead RPP', 'singular_name' => 'Lead RPP' ),
			'public'              => false,
			'publicly_queryable'  => false,
			'exclude_from_search' => true,
			'show_ui'             => false,
			'show_in_rest'        => false,
			'supports'            => array( 'title' ),
			'capability_type'     => 'post',
			'map_meta_cap'        => true,
		) );
	}

	/* =====================================================================
	   6. BACKEND
	   ===================================================================== */

	public function admin_menu() {
		$hook = add_menu_page( 'Richieste RPP', 'Lead RPP', self::CAP, 'sx-leads', array( $this, 'render_admin_page' ), 'dashicons-chart-bar', 26 );
		add_submenu_page( 'sx-leads', 'Richieste RPP', 'Richieste', self::CAP, 'sx-leads', array( $this, 'render_admin_page' ) );
		$hook2 = add_submenu_page( 'sx-leads', 'Richieste di call', 'Richieste di call', self::CAP, 'sx-calls', array( $this, 'render_calls_page' ) );
		add_submenu_page( 'sx-leads', 'Impostazioni RPP', 'Impostazioni', self::CAP, 'sx-leads-opts', array( $this, 'render_settings_page' ) );
		add_submenu_page( 'sx-leads', 'Email SMTP', 'Email SMTP', self::CAP, 'sx-smtp', array( $this, 'render_smtp_page' ) );
		add_action( 'load-' . $hook2, array( $this, 'screen_options' ) );
		add_action( 'load-' . $hook, array( $this, 'screen_options' ) );
	}

	public function screen_options() {
		add_screen_option( 'per_page', array( 'label' => 'Righe per pagina', 'default' => 25, 'option' => 'sx_leads_per_page' ) );
	}

	public function current_filters() {
		return array(
			's'        => isset( $_REQUEST['s'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['s'] ) ) : '',
			'da'       => isset( $_REQUEST['da'] ) ? $this->clean_date( wp_unslash( $_REQUEST['da'] ) ) : '',
			'a'        => isset( $_REQUEST['a'] ) ? $this->clean_date( wp_unslash( $_REQUEST['a'] ) ) : '',
			'cluster'  => ( isset( $_REQUEST['cluster'] ) && '' !== $_REQUEST['cluster'] ) ? (string) absint( $_REQUEST['cluster'] ) : '',
			'regione'  => isset( $_REQUEST['regione'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['regione'] ) ) : '',
			/* 1 = mostra solo chi ha chiesto di essere richiamato */
			'call'     => ( $this->force_call || ( isset( $_REQUEST['call'] ) && '1' === (string) $_REQUEST['call'] ) ) ? 1 : 0,
		);
	}

	private function clean_date( $d ) {
		$d = sanitize_text_field( $d );
		return preg_match( '/^\d{4}-\d{2}-\d{2}$/', $d ) ? $d : '';
	}

	public function build_query_args( $f, $per_page = 25, $paged = 1 ) {
		$args = array(
			'post_type'      => self::CPT,
			'post_status'    => 'publish',
			'posts_per_page' => $per_page,
			'paged'          => max( 1, (int) $paged ),
			'orderby'        => 'date',
			'order'          => 'DESC',
		);

		if ( '' !== $f['s'] ) { $args['s'] = $f['s']; }

		$mq = array();
		if ( ! empty( $f['call'] ) ) {
			// solo i lead che hanno premuto "Prenota la call"
			$mq[] = array( 'key' => '_sx_call', 'compare' => 'EXISTS' );
			$args['meta_key'] = '_sx_call';
			$args['orderby']  = 'meta_value';
			$args['order']    = 'DESC';
		}
		if ( '' !== $f['cluster'] ) {
			$mq[] = array( 'key' => '_sx_cluster', 'value' => (int) $f['cluster'], 'type' => 'NUMERIC', 'compare' => '=' );
		}
		if ( '' !== $f['regione'] && in_array( $f['regione'], self::regioni(), true ) ) {
			$mq[] = array( 'key' => '_sx_regione', 'value' => $f['regione'], 'compare' => '=' );
		}
		if ( $mq ) {
			$mq['relation'] = 'AND';
			$args['meta_query'] = $mq;
		}

		if ( $f['da'] || $f['a'] ) {
			$dq = array( 'inclusive' => true );
			if ( $f['da'] ) { $dq['after']  = $f['da'] . ' 00:00:00'; }
			if ( $f['a'] )  { $dq['before'] = $f['a']  . ' 23:59:59'; }
			$args['date_query'] = array( $dq );
		}

		$ob = isset( $_REQUEST['orderby'] ) ? sanitize_key( wp_unslash( $_REQUEST['orderby'] ) ) : '';
		$od = ( isset( $_REQUEST['order'] ) && 'asc' === strtolower( sanitize_key( wp_unslash( $_REQUEST['order'] ) ) ) ) ? 'ASC' : 'DESC';

		if ( 'rpp' === $ob || 'fatturato' === $ob ) {
			$args['meta_key'] = '_sx_' . $ob;
			$args['orderby']  = 'meta_value_num';
			$args['order']    = $od;
		} elseif ( 'data' === $ob ) {
			$args['order'] = $od;
		}

		return $args;
	}

	public function render_admin_page() {
		if ( ! current_user_can( self::CAP ) ) { wp_die( 'Non hai i permessi per vedere questa pagina.' ); }

		sx_leads_table_bootstrap();
		$table = new SX_Leads_Table( $this );
		$table->prepare_items();
		$f = $this->current_filters();

		$export_url = wp_nonce_url(
			add_query_arg( array_merge( array( 'action' => 'sx_lead_export' ), array_filter( $f ) ), admin_url( 'admin-post.php' ) ),
			'sx_lead_export'
		);
		?>
		<div class="wrap">
			<h1 class="wp-heading-inline">Richieste RPP</h1>
			<a href="<?php echo esc_url( $export_url ); ?>" class="page-title-action">Esporta CSV</a>
			<hr class="wp-header-end">

			<?php if ( isset( $_GET['sx_msg'] ) ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php echo esc_html( sanitize_text_field( wp_unslash( $_GET['sx_msg'] ) ) ); ?></p></div>
			<?php endif; ?>

			<form method="get">
				<input type="hidden" name="page" value="sx-leads">
				<div class="tablenav top">
					<div class="alignleft actions">
						Dal <input type="date" name="da" value="<?php echo esc_attr( $f['da'] ); ?>" aria-label="Dal giorno">
						al <input type="date" name="a" value="<?php echo esc_attr( $f['a'] ); ?>" aria-label="Al giorno">

						<select name="cluster" aria-label="Cluster">
							<option value="">Tutti i cluster</option>
							<?php for ( $i = 0; $i < 4; $i++ ) : ?>
								<option value="<?php echo esc_attr( $i ); ?>" <?php selected( $f['cluster'], (string) $i ); ?>><?php echo esc_html( $this->cluster_name( $i ) ); ?></option>
							<?php endfor; ?>
						</select>

						<select name="regione" aria-label="Regione">
							<option value="">Tutte le regioni</option>
							<?php foreach ( self::regioni() as $r ) : ?>
								<option value="<?php echo esc_attr( $r ); ?>" <?php selected( $f['regione'], $r ); ?>><?php echo esc_html( $r ); ?></option>
							<?php endforeach; ?>
						</select>

						<?php submit_button( 'Filtra', '', 'filter_action', false ); ?>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=sx-leads' ) ); ?>" class="button">Azzera</a>
					</div>
				</div>
				<?php $table->search_box( 'Cerca nome, email o telefono', 'sx-search' ); ?>
				<?php $table->display(); ?>
			</form>
		</div>
		<?php
	}

	/**
	 * Pagina "Richieste di call": solo chi ha premuto il pulsante nell'email.
	 * E' l'elenco operativo per chi in studio deve telefonare.
	 */
	public function render_calls_page() {
		if ( ! current_user_can( self::CAP ) ) { wp_die( 'Non hai i permessi per vedere questa pagina.' ); }

		$this->force_call = true;

		sx_leads_table_bootstrap();
		$table = new SX_Leads_Table( $this, 'call' );
		$table->prepare_items();
		$f = $this->current_filters();

		$export_url = wp_nonce_url(
			add_query_arg( array_merge( array( 'action' => 'sx_lead_export', 'call' => 1 ), array_filter( $f ) ), admin_url( 'admin-post.php' ) ),
			'sx_lead_export'
		);

		// quante restano da richiamare
		$pending = new WP_Query( array(
			'post_type'      => self::CPT,
			'post_status'    => 'publish',
			'posts_per_page' => 1,
			'fields'         => 'ids',
			'meta_query'     => array(
				array( 'key' => '_sx_call', 'compare' => 'EXISTS' ),
				array( 'key' => '_sx_call_stato', 'value' => 'da_contattare' ),
			),
		) );
		?>
		<div class="wrap">
			<h1 class="wp-heading-inline">Richieste di call</h1>
			<a href="<?php echo esc_url( $export_url ); ?>" class="page-title-action">Esporta CSV</a>
			<hr class="wp-header-end">

			<?php if ( isset( $_GET['sx_msg'] ) ) : ?>
				<div class="notice notice-success is-dismissible"><p><?php echo esc_html( sanitize_text_field( wp_unslash( $_GET['sx_msg'] ) ) ); ?></p></div>
			<?php endif; ?>

			<p style="font-size:14px;color:#50575e;max-width:70ch">
				Queste persone hanno chiesto di essere richiamate premendo <strong>&laquo;Prenota la call&raquo;</strong>
				nell'email del report. Vanno contattate entro 24 ore.
				<?php if ( $pending->found_posts ) : ?>
					<strong style="color:#b32d2e">Da richiamare: <?php echo (int) $pending->found_posts; ?>.</strong>
				<?php endif; ?>
			</p>

			<form method="get">
				<input type="hidden" name="page" value="sx-calls">
				<div class="tablenav top">
					<div class="alignleft actions">
						Dal <input type="date" name="da" value="<?php echo esc_attr( $f['da'] ); ?>" aria-label="Dal giorno">
						al <input type="date" name="a" value="<?php echo esc_attr( $f['a'] ); ?>" aria-label="Al giorno">

						<select name="regione" aria-label="Regione">
							<option value="">Tutte le regioni</option>
							<?php foreach ( self::regioni() as $r ) : ?>
								<option value="<?php echo esc_attr( $r ); ?>" <?php selected( $f['regione'], $r ); ?>><?php echo esc_html( $r ); ?></option>
							<?php endforeach; ?>
						</select>

						<?php submit_button( 'Filtra', '', 'filter_action', false ); ?>
						<a href="<?php echo esc_url( admin_url( 'admin.php?page=sx-calls' ) ); ?>" class="button">Azzera</a>
					</div>
				</div>
				<?php $table->search_box( 'Cerca nome, email o telefono', 'sx-search-call' ); ?>
				<?php $table->display(); ?>
			</form>
		</div>
		<?php
	}

	/** Segna un contatto come gia' richiamato. */
	public function handle_mark_called() {
		if ( ! current_user_can( self::CAP ) ) { wp_die( 'Permessi insufficienti.', '', array( 'response' => 403 ) ); }

		$id = isset( $_GET['lead'] ) ? absint( $_GET['lead'] ) : 0;
		check_admin_referer( 'sx_lead_called_' . $id );

		if ( $id && get_post_type( $id ) === self::CPT ) {
			$done = 'contattato' === get_post_meta( $id, '_sx_call_stato', true );
			update_post_meta( $id, '_sx_call_stato', $done ? 'da_contattare' : 'contattato' );
			update_post_meta( $id, '_sx_call_op', $done ? '' : wp_get_current_user()->display_name );
		}
		wp_safe_redirect( add_query_arg( 'sx_msg', rawurlencode( 'Stato aggiornato.' ), admin_url( 'admin.php?page=sx-calls' ) ) );
		exit;
	}

	public function render_settings_page() {
		if ( ! current_user_can( self::CAP ) ) { wp_die( 'Permessi insufficienti.' ); }
		$o = $this->opts();
		?>
		<div class="wrap">
			<h1>Impostazioni StudioIndex</h1>

			<?php if ( isset( $_GET['sx_saved'] ) ) : ?>
				<div class="notice notice-success is-dismissible"><p>Impostazioni salvate.</p></div>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="sx_save_opts">
				<?php wp_nonce_field( 'sx_save_opts' ); ?>

				<h2 class="title">Protezione antispam (reCAPTCHA)</h2>
				<p>Le chiavi si ottengono gratuitamente su
				<a href="https://www.google.com/recaptcha/admin" target="_blank" rel="noopener">google.com/recaptcha/admin</a>.
				Ricordati di registrare il dominio del sito.</p>

				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="sx-rc">Modalit&agrave;</label></th>
						<td>
							<select name="recaptcha" id="sx-rc">
								<option value="off" <?php selected( $o['recaptcha'], 'off' ); ?>>Disattivato</option>
								<option value="v3"  <?php selected( $o['recaptcha'], 'v3' ); ?>>reCAPTCHA v3 (invisibile, consigliato)</option>
								<option value="v2"  <?php selected( $o['recaptcha'], 'v2' ); ?>>reCAPTCHA v2 (casella "Non sono un robot")</option>
							</select>
							<p class="description">Il blocco in pagina si adatta da solo: non serve modificare l'HTML.</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="sx-sk">Site key</label></th>
						<td><input type="text" id="sx-sk" name="site_key" class="regular-text code" value="<?php echo esc_attr( $o['site_key'] ); ?>" autocomplete="off"></td>
					</tr>
					<tr>
						<th scope="row"><label for="sx-ck">Secret key</label></th>
						<td>
							<input type="password" id="sx-ck" name="secret_key" class="regular-text code" value="<?php echo esc_attr( $o['secret_key'] ); ?>" autocomplete="new-password">
							<p class="description">Resta sul server: non viene mai inviata al browser.</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="sx-score">Soglia punteggio (solo v3)</label></th>
						<td>
							<input type="number" id="sx-score" name="score" step="0.1" min="0" max="1" value="<?php echo esc_attr( $o['score'] ); ?>" class="small-text">
							<p class="description">0,5 &egrave; il valore consigliato. Pi&ugrave; alto = pi&ugrave; severo (rischio di bloccare utenti veri).</p>
						</td>
					</tr>
				</table>

				<h2 class="title">Destinatari delle notifiche</h2>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row">Copia interna</th>
						<td>
							<label for="sx-notify-on">
								<input type="checkbox" id="sx-notify-on" name="notify_on" value="1" <?php checked( (int) $o['notify_on'], 1 ); ?>>
								Invia una copia del report anche allo studio e all'amministratore
							</label>
							<p class="description">Se resta disattivato, il PDF arriva <strong>solo all'utente</strong>. Le richieste restano comunque registrate nel menu "Richieste".</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="sx-notify">Indirizzi</label></th>
						<td>
							<textarea id="sx-notify" name="notify" rows="4" class="large-text code"><?php echo esc_textarea( $o['notify'] ); ?></textarea>
							<p class="description">Uno per riga. Il primo indirizzo &egrave; sempre usato come Reply-To nell'email inviata all'utente, anche con la copia interna disattivata.</p>
						</td>
					</tr>
				</table>

				<?php submit_button( 'Salva impostazioni' ); ?>
			</form>

			<hr>
			<h2>Stato del sistema</h2>
			<table class="widefat striped" style="max-width:640px">
				<tbody>
					<tr><td>Endpoint del modulo</td><td><code><?php echo esc_html( rest_url( self::NS . '/report' ) ); ?></code></td></tr>
					<tr><td>Limite per IP</td><td><?php echo esc_html( self::RATE_IP_HOUR ); ?> all'ora, <?php echo esc_html( self::RATE_IP_DAY ); ?> al giorno</td></tr>
					<tr><td>Limite per email</td><td><?php echo esc_html( self::RATE_MAIL_DAY ); ?> al giorno</td></tr>
					<tr><td>Cartella dei PDF</td><td><code><?php $u = wp_upload_dir(); echo esc_html( trailingslashit( $u['basedir'] ) . 'studioindex-reports' ); ?></code></td></tr>
				</tbody>
			</table>
		</div>
		<?php
	}

	public function handle_save_settings() {
		if ( ! current_user_can( self::CAP ) ) { wp_die( 'Permessi insufficienti.', '', array( 'response' => 403 ) ); }
		check_admin_referer( 'sx_save_opts' );

		$mode = isset( $_POST['recaptcha'] ) ? sanitize_key( wp_unslash( $_POST['recaptcha'] ) ) : 'off';
		if ( ! in_array( $mode, array( 'off', 'v2', 'v3' ), true ) ) { $mode = 'off'; }

		$score = isset( $_POST['score'] ) ? (float) wp_unslash( $_POST['score'] ) : 0.5;
		$score = max( 0, min( 1, $score ) );

		$notify = isset( $_POST['notify'] ) ? sanitize_textarea_field( wp_unslash( $_POST['notify'] ) ) : '';

		update_option( self::OPTION, array(
			'recaptcha'  => $mode,
			'site_key'   => isset( $_POST['site_key'] ) ? sanitize_text_field( wp_unslash( $_POST['site_key'] ) ) : '',
			'secret_key' => isset( $_POST['secret_key'] ) ? sanitize_text_field( wp_unslash( $_POST['secret_key'] ) ) : '',
			'score'      => $score,
			'notify_on'  => ( isset( $_POST['notify_on'] ) && '1' === (string) wp_unslash( $_POST['notify_on'] ) ) ? 1 : 0,
			'notify'     => $notify,
		), false );

		wp_safe_redirect( add_query_arg( 'sx_saved', '1', admin_url( 'admin.php?page=sx-leads-opts' ) ) );
		exit;
	}

	/* =====================================================================
	   6b. EMAIL / SMTP
	   Il server SMTP si imposta da "Lead RPP > Email SMTP". Vale SOLO per le
	   email di questo plugin: le altre email del sito non vengono toccate.
	   ===================================================================== */

	public function smtp_opts() {
		$d = array(
			'enabled'     => 0,
			'host'        => '',
			'port'        => 465,
			'secure'      => 'ssl',   // ssl | tls | none
			'auth'        => 1,
			'user'        => '',
			'pass'        => '',      // cifrata, vedi smtp_encrypt()
			'from_email'  => '',      // vuoto = utente SMTP se e' un indirizzo email
			'from_name'   => '',
			'verify_cert' => 1,
		);
		$o = get_option( self::SMTP_OPTION, array() );
		return wp_parse_args( is_array( $o ) ? $o : array(), $d );
	}

	private function smtp_active() {
		$s = $this->smtp_opts();
		return ! empty( $s['enabled'] ) && '' !== trim( (string) $s['host'] );
	}

	private function smtp_from_address() {
		$s = $this->smtp_opts();
		$f = sanitize_email( (string) $s['from_email'] );
		if ( is_email( $f ) ) { return $f; }
		return is_email( $s['user'] ) ? $s['user'] : '';
	}

	/* --- password: mai in chiaro nel database, mai restituita al browser --- */

	private function smtp_key() {
		return hash( 'sha256', wp_salt( 'auth' ), true );
	}

	private function smtp_encrypt( $plain ) {
		if ( '' === $plain ) { return ''; }
		if ( function_exists( 'sodium_crypto_secretbox' ) ) {
			$nonce = random_bytes( 24 );   // lunghezza fissa del nonce di secretbox
			return 'enc1:' . base64_encode( $nonce . sodium_crypto_secretbox( $plain, $nonce, $this->smtp_key() ) );
		}
		return 'raw:' . $plain;   // ambiente senza libsodium: meglio funzionare che fallire
	}

	private function smtp_decrypt( $stored ) {
		$stored = (string) $stored;
		if ( 0 === strpos( $stored, 'raw:' ) ) { return substr( $stored, 4 ); }
		if ( 0 !== strpos( $stored, 'enc1:' ) || ! function_exists( 'sodium_crypto_secretbox_open' ) ) { return ''; }

		$bin = base64_decode( substr( $stored, 5 ), true );
		$nl  = 24;
		if ( false === $bin || strlen( $bin ) <= $nl ) { return ''; }

		$plain = sodium_crypto_secretbox_open( substr( $bin, $nl ), substr( $bin, 0, $nl ), $this->smtp_key() );
		return false === $plain ? '' : $plain;   // '' se le chiavi di WordPress sono cambiate
	}

	private function smtp_password() {
		return $this->smtp_decrypt( $this->smtp_opts()['pass'] );
	}

	/* --- aggancio a wp_mail: attivo solo mentre il plugin invia --- */

	private function mail_hooks_on() {
		add_filter( 'wp_mail_from',         array( $this, 'f_from' ) );
		add_filter( 'wp_mail_from_name',    array( $this, 'f_from_name' ) );
		add_filter( 'wp_mail_content_type', array( $this, 'f_html' ) );
		// priorita' alta: se c'e' anche un altro plugin SMTP, vince questo quando e' attivo.
		add_action( 'phpmailer_init',       array( $this, 'smtp_configure' ), 99 );
	}

	private function mail_hooks_off() {
		remove_filter( 'wp_mail_from',         array( $this, 'f_from' ) );
		remove_filter( 'wp_mail_from_name',    array( $this, 'f_from_name' ) );
		remove_filter( 'wp_mail_content_type', array( $this, 'f_html' ) );
		remove_action( 'phpmailer_init',       array( $this, 'smtp_configure' ), 99 );
	}

	/** Passa PHPMailer sul server SMTP impostato. */
	public function smtp_configure( $phpmailer ) {
		if ( ! $this->smtp_active() ) { return; }
		$s = $this->smtp_opts();

		$phpmailer->isSMTP();
		$phpmailer->Host        = $s['host'];
		$phpmailer->Port        = (int) $s['port'];
		$phpmailer->SMTPSecure  = ( 'none' === $s['secure'] ) ? '' : $s['secure'];
		$phpmailer->SMTPAutoTLS = ( 'none' !== $s['secure'] );
		$phpmailer->SMTPAuth    = ! empty( $s['auth'] );
		$phpmailer->Timeout     = 15;   // il default (300 s) bloccherebbe il visitatore

		if ( $phpmailer->SMTPAuth ) {
			$phpmailer->Username = $s['user'];
			$phpmailer->Password = $this->smtp_password();
		}

		if ( empty( $s['verify_cert'] ) ) {
			$phpmailer->SMTPOptions = array( 'ssl' => array(
				'verify_peer'       => false,
				'verify_peer_name'  => false,
				'allow_self_signed' => true,
			) );
		}

		// Return-Path uguale al mittente: molti server rifiutano un envelope diverso.
		if ( is_email( $phpmailer->From ) ) { $phpmailer->Sender = $phpmailer->From; }
	}

	/* --- invio di prova: registra il dialogo col server --- */

	public function smtp_debug( $phpmailer ) {
		$phpmailer->SMTPDebug   = 2;
		$phpmailer->Debugoutput = array( $this, 'smtp_log_line' );
	}

	public function smtp_log_line( $str, $level = 0 ) {
		$str = trim( (string) $str );

		// Mai registrare le credenziali: la password viaggia in base64.
		$str = preg_replace( '/(CLIENT -> SERVER:\s*)[A-Za-z0-9+\/=]{12,}\s*$/', '$1[nascosto]', $str );
		$str = preg_replace( '/(AUTH\s+(?:PLAIN|LOGIN|XOAUTH2)\s+)\S+/i', '$1[nascosto]', $str );
		$pw  = $this->smtp_password();
		if ( '' !== $pw ) {
			$str = str_replace( array( $pw, base64_encode( $pw ) ), '[nascosto]', $str );
		}

		$this->smtp_log[] = $str;
	}

	public function smtp_capture_error( $err ) {
		if ( is_wp_error( $err ) ) { $this->smtp_err = $err->get_error_message(); }
	}

	/* --- pagina di amministrazione --- */

	public function render_smtp_page() {
		if ( ! current_user_can( self::CAP ) ) { wp_die( 'Permessi insufficienti.' ); }

		$s      = $this->smtp_opts();
		$active = $this->smtp_active();
		$pw_set = '' !== (string) $s['pass'];
		$pw_bad = $pw_set && '' === $this->smtp_password();
		$notice = isset( $_GET['sx_smtp'] ) ? sanitize_key( wp_unslash( $_GET['sx_smtp'] ) ) : '';
		$labels = array(
			'ssl'  => 'SSL/TLS (consigliato, porta 465)',
			'tls'  => 'STARTTLS (porta 587)',
			'none' => 'Nessuna (porta 25, sconsigliato)',
		);

		$test = false;
		if ( isset( $_GET['sx_tested'] ) ) {
			$key  = 'sx_smtp_test_' . get_current_user_id();
			$test = get_transient( $key );
			delete_transient( $key );
		}
		$me = wp_get_current_user();
		?>
		<div class="wrap">
			<h1>Email SMTP</h1>

			<?php if ( 'saved' === $notice ) : ?>
				<div class="notice notice-success is-dismissible"><p>Impostazioni SMTP salvate.</p></div>
			<?php elseif ( 'incomplete' === $notice ) : ?>
				<div class="notice notice-warning is-dismissible"><p>Impostazioni salvate, ma l'SMTP <strong>non &egrave; stato attivato</strong>: servono il server e, se l'autenticazione &egrave; richiesta, utente e password.</p></div>
			<?php elseif ( 'badmail' === $notice ) : ?>
				<div class="notice notice-error is-dismissible"><p>Indirizzo di prova non valido.</p></div>
			<?php endif; ?>

			<?php if ( is_array( $test ) ) : ?>
				<div class="notice notice-<?php echo ! empty( $test['ok'] ) ? 'success' : 'error'; ?>">
					<?php if ( ! empty( $test['ok'] ) ) : ?>
						<p><strong>Il server ha accettato l'email di prova per <?php echo esc_html( $test['to'] ); ?>.</strong>
						Controlla la casella (anche lo spam)<?php echo empty( $test['smtp'] ) ? '. Nota: l\'SMTP non &egrave; attivo, il test &egrave; partito con l\'invio predefinito del sito' : ''; ?>.</p>
					<?php else : ?>
						<p><strong>Invio non riuscito.</strong> <?php echo esc_html( $test['error'] ); ?></p>
					<?php endif; ?>
					<?php if ( ! empty( $test['log'] ) ) : ?>
						<details style="margin:0 0 12px">
							<summary>Dettagli tecnici</summary>
							<pre style="white-space:pre-wrap;max-height:320px;overflow:auto;background:#f6f7f7;padding:10px;margin-top:8px"><?php echo esc_html( $test['log'] ); ?></pre>
						</details>
					<?php endif; ?>
				</div>
			<?php endif; ?>

			<?php if ( $active ) : ?>
				<div class="notice notice-info inline"><p>
					SMTP <strong>attivo</strong>:
					<code><?php echo esc_html( $s['host'] . ':' . (int) $s['port'] ); ?></code>
					(<?php echo esc_html( strtoupper( $s['secure'] ) ); ?>),
					mittente <code><?php echo esc_html( $this->smtp_from_address() ? $this->smtp_from_address() : '—' ); ?></code>.
				</p></div>
			<?php else : ?>
				<div class="notice notice-warning inline"><p>SMTP <strong>non attivo</strong>: le email partono con l'invio predefinito del sito (o con il plugin SMTP eventualmente installato).</p></div>
			<?php endif; ?>

			<?php if ( $pw_bad ) : ?>
				<div class="notice notice-error inline"><p>La password salvata non &egrave; pi&ugrave; leggibile (le chiavi di sicurezza di WordPress sono cambiate). Reinseriscila e salva.</p></div>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="sx_save_smtp">
				<?php wp_nonce_field( 'sx_save_smtp' ); ?>

				<h2 class="title">Server di posta in uscita</h2>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row">Stato</th>
						<td>
							<label for="sx-smtp-on">
								<input type="checkbox" id="sx-smtp-on" name="smtp_enabled" value="1" <?php checked( (int) $s['enabled'], 1 ); ?>>
								Invia le email del plugin tramite questo server SMTP
							</label>
							<p class="description">Se disattivato, il plugin usa l'invio predefinito del sito. Le altre email di WordPress non vengono toccate.</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="sx-smtp-host">Server SMTP</label></th>
						<td><input type="text" id="sx-smtp-host" name="smtp_host" class="regular-text code" value="<?php echo esc_attr( $s['host'] ); ?>" placeholder="mail.studioindex.it" autocomplete="off"></td>
					</tr>
					<tr>
						<th scope="row"><label for="sx-smtp-secure">Crittografia</label></th>
						<td>
							<select name="smtp_secure" id="sx-smtp-secure">
								<?php foreach ( $labels as $k => $l ) : ?>
									<option value="<?php echo esc_attr( $k ); ?>" <?php selected( $s['secure'], $k ); ?>><?php echo esc_html( $l ); ?></option>
								<?php endforeach; ?>
							</select>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="sx-smtp-port">Porta</label></th>
						<td><input type="number" id="sx-smtp-port" name="smtp_port" class="small-text" min="1" max="65535" value="<?php echo esc_attr( (int) $s['port'] ); ?>"></td>
					</tr>
					<tr>
						<th scope="row">Autenticazione</th>
						<td>
							<label for="sx-smtp-auth">
								<input type="checkbox" id="sx-smtp-auth" name="smtp_auth" value="1" <?php checked( (int) $s['auth'], 1 ); ?>>
								Il server richiede utente e password
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="sx-smtp-user">Utente</label></th>
						<td><input type="text" id="sx-smtp-user" name="smtp_user" class="regular-text" value="<?php echo esc_attr( $s['user'] ); ?>" placeholder="staff@studioindex.it" autocomplete="off"></td>
					</tr>
					<tr>
						<th scope="row"><label for="sx-smtp-pass">Password</label></th>
						<td>
							<input type="password" id="sx-smtp-pass" name="smtp_pass" class="regular-text" value="" autocomplete="new-password"
								placeholder="<?php echo $pw_set ? '&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull; (salvata)' : ''; ?>">
							<p class="description">
								<?php echo $pw_set ? 'Password salvata. Lascia vuoto per non cambiarla.' : 'Nessuna password salvata.'; ?>
								Viene conservata cifrata e non viene mai mostrata di nuovo.
							</p>
						</td>
					</tr>
				</table>

				<h2 class="title">Mittente</h2>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><label for="sx-smtp-from">Email mittente</label></th>
						<td>
							<input type="email" id="sx-smtp-from" name="smtp_from_email" class="regular-text" value="<?php echo esc_attr( $s['from_email'] ); ?>" placeholder="staff@studioindex.it">
							<p class="description">Se vuoto si usa l'utente SMTP. Deve essere un indirizzo del dominio del server, altrimenti il messaggio viene rifiutato o finisce nello spam.</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><label for="sx-smtp-fname">Nome mittente</label></th>
						<td><input type="text" id="sx-smtp-fname" name="smtp_from_name" class="regular-text" maxlength="<?php echo esc_attr( self::MAX_NOME ); ?>" value="<?php echo esc_attr( $s['from_name'] ); ?>" placeholder="StudioIndex"></td>
					</tr>
				</table>

				<h2 class="title">Avanzate</h2>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row">Certificato SSL</th>
						<td>
							<label for="sx-smtp-verify">
								<input type="checkbox" id="sx-smtp-verify" name="smtp_verify" value="1" <?php checked( (int) $s['verify_cert'], 1 ); ?>>
								Verifica il certificato del server (consigliato)
							</label>
							<p class="description">Disattivalo solo se l'invio di prova fallisce con un errore di certificato, tipico di alcuni hosting condivisi dove il certificato &egrave; intestato a un altro nome.</p>
						</td>
					</tr>
				</table>

				<?php submit_button( 'Salva impostazioni SMTP' ); ?>
			</form>

			<hr>
			<h2>Invio di prova</h2>
			<p>Usa le impostazioni <strong>gi&agrave; salvate</strong>: salva prima, poi prova.</p>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="sx_smtp_test">
				<?php wp_nonce_field( 'sx_smtp_test' ); ?>
				<input type="email" name="test_to" class="regular-text" required value="<?php echo esc_attr( $me->user_email ); ?>" aria-label="Indirizzo di prova">
				<?php submit_button( 'Invia email di prova', 'secondary', 'submit', false ); ?>
			</form>
		</div>

		<script>
		(function () {
			var sel = document.getElementById('sx-smtp-secure'), port = document.getElementById('sx-smtp-port');
			if (!sel || !port) { return; }
			var map = { ssl: '465', tls: '587', none: '25' };
			sel.addEventListener('change', function () {
				// cambia la porta solo se e' ancora una di quelle standard
				if (['', '25', '465', '587'].indexOf(port.value) > -1) { port.value = map[sel.value]; }
			});
		})();
		</script>
		<?php
	}

	public function handle_save_smtp() {
		if ( ! current_user_can( self::CAP ) ) { wp_die( 'Permessi insufficienti.', '', array( 'response' => 403 ) ); }
		check_admin_referer( 'sx_save_smtp' );

		$old = $this->smtp_opts();
		$in  = function ( $k ) { return isset( $_POST[ $k ] ) ? (string) wp_unslash( $_POST[ $k ] ) : ''; };

		$secure = sanitize_key( $in( 'smtp_secure' ) );
		if ( ! in_array( $secure, array( 'ssl', 'tls', 'none' ), true ) ) { $secure = 'ssl'; }

		// solo il nome del server: via eventuale "ssl://" e caratteri non validi
		$host = strtolower( trim( sanitize_text_field( $in( 'smtp_host' ) ) ) );
		$host = preg_replace( '#^[a-z]+://#', '', $host );
		$host = preg_replace( '/[^a-z0-9.\-]/', '', $host );

		$port = absint( $in( 'smtp_port' ) );
		if ( $port < 1 || $port > 65535 ) {
			$port = array( 'ssl' => 465, 'tls' => 587, 'none' => 25 )[ $secure ];
		}

		$auth = '1' === $in( 'smtp_auth' ) ? 1 : 0;
		$user = trim( str_replace( array( "\r", "\n", "\0" ), '', $in( 'smtp_user' ) ) );

		// La password NON va sanitizzata (puo' contenere < % & ecc.): si tolgono
		// solo i caratteri di controllo. Se il campo e' vuoto resta quella salvata.
		$pass_in = str_replace( array( "\r", "\n", "\0" ), '', $in( 'smtp_pass' ) );
		$pass    = '' !== $pass_in ? $this->smtp_encrypt( substr( $pass_in, 0, 256 ) ) : (string) $old['pass'];

		$from_email = sanitize_email( $in( 'smtp_from_email' ) );
		$from_name  = $this->header_safe( sanitize_text_field( $in( 'smtp_from_name' ) ) );

		$enabled    = '1' === $in( 'smtp_enabled' ) ? 1 : 0;
		$incomplete = false;
		if ( $enabled && ( '' === $host || ( $auth && ( '' === $user || '' === $pass ) ) ) ) {
			$enabled    = 0;
			$incomplete = true;
		}

		update_option( self::SMTP_OPTION, array(
			'enabled'     => $enabled,
			'host'        => $host,
			'port'        => $port,
			'secure'      => $secure,
			'auth'        => $auth,
			'user'        => $user,
			'pass'        => $pass,
			'from_email'  => $from_email,
			'from_name'   => substr( $from_name, 0, self::MAX_NOME ),
			'verify_cert' => '1' === $in( 'smtp_verify' ) ? 1 : 0,
		), false );

		wp_safe_redirect( add_query_arg( 'sx_smtp', $incomplete ? 'incomplete' : 'saved', admin_url( 'admin.php?page=sx-smtp' ) ) );
		exit;
	}

	public function handle_smtp_test() {
		if ( ! current_user_can( self::CAP ) ) { wp_die( 'Permessi insufficienti.', '', array( 'response' => 403 ) ); }
		check_admin_referer( 'sx_smtp_test' );

		$to = isset( $_POST['test_to'] ) ? sanitize_email( wp_unslash( $_POST['test_to'] ) ) : '';
		if ( ! is_email( $to ) ) {
			wp_safe_redirect( add_query_arg( 'sx_smtp', 'badmail', admin_url( 'admin.php?page=sx-smtp' ) ) );
			exit;
		}

		$this->smtp_log = array();
		$this->smtp_err = '';

		$this->mail_hooks_on();
		add_action( 'phpmailer_init', array( $this, 'smtp_debug' ), 100 );
		add_action( 'wp_mail_failed', array( $this, 'smtp_capture_error' ) );

		$ok = wp_mail(
			$to,
			'Prova SMTP — StudioIndex',
			'<p>Questa &egrave; un\'email di prova inviata dal plugin StudioIndex.</p>'
				. '<p>Se la leggi, il server SMTP &egrave; configurato correttamente.</p>'
		);

		remove_action( 'wp_mail_failed', array( $this, 'smtp_capture_error' ) );
		remove_action( 'phpmailer_init', array( $this, 'smtp_debug' ), 100 );
		$this->mail_hooks_off();

		$log = implode( "\n", $this->smtp_log );
		if ( strlen( $log ) > 12000 ) { $log = substr( $log, 0, 12000 ) . "\n[... troncato]"; }

		set_transient( 'sx_smtp_test_' . get_current_user_id(), array(
			'ok'    => (bool) $ok,
			'to'    => $to,
			'smtp'  => $this->smtp_active(),
			'error' => '' !== $this->smtp_err ? $this->smtp_err : 'Errore sconosciuto.',
			'log'   => $log,
		), 10 * MINUTE_IN_SECONDS );

		wp_safe_redirect( add_query_arg( 'sx_tested', '1', admin_url( 'admin.php?page=sx-smtp' ) ) );
		exit;
	}

	/* =====================================================================
	   7. AZIONI
	   ===================================================================== */

	public function handle_pdf_download() {
		if ( ! current_user_can( self::CAP ) ) { wp_die( 'Permessi insufficienti.', '', array( 'response' => 403 ) ); }

		$id = isset( $_GET['lead'] ) ? absint( $_GET['lead'] ) : 0;
		check_admin_referer( 'sx_lead_pdf_' . $id );

		if ( ! $id || get_post_type( $id ) !== self::CPT ) { wp_die( 'Richiesta non valida.', '', array( 'response' => 400 ) ); }

		$real = $this->safe_pdf_path( $id );
		if ( ! $real ) { wp_die( 'Il PDF non e\' piu\' disponibile.', '', array( 'response' => 404 ) ); }

		nocache_headers();
		header( 'Content-Type: application/pdf' );
		header( 'Content-Disposition: inline; filename="report-rpp-' . $id . '.pdf"' );
		header( 'Content-Length: ' . filesize( $real ) );
		header( 'X-Content-Type-Options: nosniff' );
		readfile( $real );
		exit;
	}

	public function handle_delete() {
		if ( ! current_user_can( self::CAP ) ) { wp_die( 'Permessi insufficienti.', '', array( 'response' => 403 ) ); }

		$id = isset( $_GET['lead'] ) ? absint( $_GET['lead'] ) : 0;
		check_admin_referer( 'sx_lead_delete_' . $id );

		if ( $id && get_post_type( $id ) === self::CPT ) { wp_delete_post( $id, true ); }

		wp_safe_redirect( add_query_arg( 'sx_msg', rawurlencode( 'Richiesta eliminata.' ), admin_url( 'admin.php?page=sx-leads' ) ) );
		exit;
	}

	public function handle_export() {
		if ( ! current_user_can( self::CAP ) ) { wp_die( 'Permessi insufficienti.', '', array( 'response' => 403 ) ); }
		check_admin_referer( 'sx_lead_export' );

		$query = new WP_Query( $this->build_query_args( $this->current_filters(), 5000, 1 ) );

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		$f_now = $this->current_filters();
		$base  = ! empty( $f_now['call'] ) ? 'call-rpp-' : 'lead-rpp-';
		header( 'Content-Disposition: attachment; filename="' . $base . gmdate( 'Y-m-d' ) . '.csv"' );

		$out = fopen( 'php://output', 'w' );
		fwrite( $out, "\xEF\xBB\xBF" );
		fputcsv( $out, array( 'Data', 'Nome', 'Email', 'Telefono', 'Attivita', 'Regione', 'Fatturato', 'Addetti', 'RPP', 'Cluster', 'IP', 'Email inviata', 'Call richiesta il', 'Stato call' ), ';' );

		foreach ( $query->posts as $p ) {
			fputcsv( $out, array(
				get_the_date( 'd/m/Y H:i', $p ),
				(string) get_post_meta( $p->ID, '_sx_nome', true ),
				(string) get_post_meta( $p->ID, '_sx_email', true ),
				(string) get_post_meta( $p->ID, '_sx_telefono', true ),
				(string) get_post_meta( $p->ID, '_sx_attivita', true ),
				(string) get_post_meta( $p->ID, '_sx_regione', true ),
				(string) get_post_meta( $p->ID, '_sx_fatturato', true ),
				str_replace( '.', ',', (string) get_post_meta( $p->ID, '_sx_addetti', true ) ),
				(string) get_post_meta( $p->ID, '_sx_rpp', true ),
				(string) get_post_meta( $p->ID, '_sx_cluster_n', true ),
				(string) get_post_meta( $p->ID, '_sx_ip', true ),
				get_post_meta( $p->ID, '_sx_sent', true ) ? 'si' : 'no',
				(string) get_post_meta( $p->ID, '_sx_call', true ),
				(string) get_post_meta( $p->ID, '_sx_call_stato', true ),
			), ';' );
		}
		fclose( $out );
		exit;
	}
}

/* =========================================================================
   TABELLA DELLE RICHIESTE
   ========================================================================= */
function sx_leads_table_bootstrap() {
	if ( class_exists( 'SX_Leads_Table' ) ) { return; }
	if ( ! class_exists( 'WP_List_Table' ) ) {
		require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
	}

	class SX_Leads_Table extends WP_List_Table {

		private $plugin;
		private $mode;   // 'list' = tutte le richieste, 'call' = solo da richiamare

		public function __construct( $plugin, $mode = 'list' ) {
			$this->plugin = $plugin;
			$this->mode   = $mode;
			parent::__construct( array( 'singular' => 'lead', 'plural' => 'lead', 'ajax' => false ) );
		}

		public function get_columns() {
			if ( 'call' === $this->mode ) {
				return array(
					'chiesta'   => 'Richiesta il',
					'nome'      => 'Nome',
					'telefono'  => 'Telefono',
					'email'     => 'Email',
					'attivita'  => 'Attività',
					'regione'   => 'Regione',
					'fatturato' => 'Fatturato',
					'rpp'       => 'RPP',
					'cluster'   => 'Cluster',
					'stato'     => 'Stato',
					'pdf'       => 'Report',
				);
			}
			return array(
				'data'      => 'Data',
				'nome'      => 'Nome',
				'email'     => 'Email',
				'telefono'  => 'Telefono',
				'attivita'  => 'Attività',
				'regione'   => 'Regione',
				'fatturato' => 'Fatturato',
				'addetti'   => 'Add.',
				'rpp'       => 'RPP',
				'cluster'   => 'Cluster',
				'pdf'       => 'Report',
			);
		}

		public function get_sortable_columns() {
			if ( 'call' === $this->mode ) {
				return array( 'rpp' => array( 'rpp', false ), 'fatturato' => array( 'fatturato', false ) );
			}
			return array(
				'data'      => array( 'data', true ),
				'rpp'       => array( 'rpp', false ),
				'fatturato' => array( 'fatturato', false ),
			);
		}

		public function no_items() {
			echo 'call' === $this->mode
				? 'Nessuno ha ancora prenotato una call.'
				: 'Nessuna richiesta trovata con questi filtri.';
		}

		public function prepare_items() {
			$per_page = (int) get_user_option( 'sx_leads_per_page' );
			if ( $per_page < 1 ) { $per_page = 25; }

			$paged = isset( $_REQUEST['paged'] ) ? absint( $_REQUEST['paged'] ) : 1;
			$q     = new WP_Query( $this->plugin->build_query_args( $this->plugin->current_filters(), $per_page, $paged ) );

			$this->items           = $q->posts;
			$this->_column_headers = array( $this->get_columns(), array(), $this->get_sortable_columns(), 'nome' );

			$this->set_pagination_args( array(
				'total_items' => (int) $q->found_posts,
				'per_page'    => $per_page,
				'total_pages' => (int) $q->max_num_pages,
			) );
		}

		private function meta( $post, $key ) {
			return (string) get_post_meta( $post->ID, '_sx_' . $key, true );
		}

		public function column_default( $post, $column ) {
			switch ( $column ) {

				case 'data':
					return esc_html( get_the_date( 'd/m/Y', $post ) )
						. '<br><span style="color:#888">' . esc_html( get_the_date( 'H:i', $post ) ) . '</span>'
						. '<br><span style="color:#aaa;font-family:monospace;font-size:11px">' . esc_html( $this->meta( $post, 'ip' ) ) . '</span>';

				case 'nome':
					$del = wp_nonce_url( admin_url( 'admin-post.php?action=sx_lead_delete&lead=' . $post->ID ), 'sx_lead_delete_' . $post->ID );
					$badge = get_post_meta( $post->ID, '_sx_sent', true ) ? '' : ' <span title="Email non consegnata" style="color:#b32d2e">&#9679;</span>';
					if ( 'call' !== $this->mode && $this->meta( $post, 'call' ) ) {
						$badge .= ' <span title="Ha prenotato una call" style="display:inline-block;padding:1px 7px;border-radius:10px;background:#123B3E;color:#fff;font-size:10px;font-weight:600">CALL</span>';
					}
					$actions = array(
						'delete' => '<a href="' . esc_url( $del ) . '" style="color:#b32d2e" onclick="return confirm(\'Eliminare definitivamente questa richiesta e il suo PDF?\')">Elimina</a>',
					);
					return '<strong>' . esc_html( $this->meta( $post, 'nome' ) ) . '</strong>' . $badge . $this->row_actions( $actions );

				case 'email':
					$m = $this->meta( $post, 'email' );
					return '<a href="mailto:' . esc_attr( $m ) . '" style="word-break:break-all">' . esc_html( $m ) . '</a>';

				case 'telefono':
					$t = $this->meta( $post, 'telefono' );
					return '<a href="tel:' . esc_attr( preg_replace( '/[^\d+]/', '', $t ) ) . '" style="white-space:nowrap">' . esc_html( $t ) . '</a>';

				case 'chiesta':
					$d = $this->meta( $post, 'call' );
					$ts = $d ? strtotime( $d ) : 0;
					if ( ! $ts ) { return '—'; }
					$ore = ( current_time( 'timestamp' ) - $ts ) / HOUR_IN_SECONDS;
					$late = ( $ore > 24 && 'contattato' !== $this->meta( $post, 'call_stato' ) );
					return esc_html( date_i18n( 'd/m/Y', $ts ) )
						. '<br><span style="color:#888">' . esc_html( date_i18n( 'H:i', $ts ) ) . '</span>'
						. ( $late ? '<br><span style="color:#b32d2e;font-size:11px;font-weight:600">oltre 24 ore</span>' : '' );

				case 'stato':
					$done = 'contattato' === $this->meta( $post, 'call_stato' );
					$op   = $this->meta( $post, 'call_op' );
					$url  = wp_nonce_url( admin_url( 'admin-post.php?action=sx_lead_called&lead=' . $post->ID ), 'sx_lead_called_' . $post->ID );
					$html = $done
						? '<span style="display:inline-block;padding:2px 9px;border-radius:11px;background:#2C6B4A;color:#fff;font-size:11px">Contattato</span>'
						: '<span style="display:inline-block;padding:2px 9px;border-radius:11px;background:#BC862A;color:#fff;font-size:11px">Da richiamare</span>';
					if ( $done && $op ) { $html .= '<br><span style="color:#888;font-size:11px">da ' . esc_html( $op ) . '</span>'; }
					$html .= '<br><a href="' . esc_url( $url ) . '" style="font-size:11px">'
						. ( $done ? 'Riapri' : 'Segna come contattato' ) . '</a>';
					return $html;

				case 'attivita':
					return esc_html( $this->meta( $post, 'attivita' ) );

				case 'regione':
					return esc_html( $this->meta( $post, 'regione' ) );

				case 'fatturato':
					return '&euro; ' . esc_html( number_format( (float) $this->meta( $post, 'fatturato' ), 0, ',', '.' ) );

				case 'addetti':
					return esc_html( str_replace( '.', ',', $this->meta( $post, 'addetti' ) ) );

				case 'rpp':
					return '<strong>&euro; ' . esc_html( number_format( (float) $this->meta( $post, 'rpp' ), 0, ',', '.' ) ) . '</strong>';

				case 'cluster':
					$i   = (int) $this->meta( $post, 'cluster' );
					$col = array( '#AE3F2E', '#BC862A', '#2E7A72', '#2C6B4A' );
					$bg  = isset( $col[ $i ] ) ? $col[ $i ] : '#666';
					return '<span style="display:inline-block;padding:2px 9px;border-radius:11px;background:' . esc_attr( $bg ) . ';color:#fff;font-size:11px;white-space:nowrap">'
						. esc_html( $this->meta( $post, 'cluster_n' ) ) . '</span>';

				case 'pdf':
					$url = wp_nonce_url( admin_url( 'admin-post.php?action=sx_lead_pdf&lead=' . $post->ID ), 'sx_lead_pdf_' . $post->ID );
					return '<a class="button button-small" href="' . esc_url( $url ) . '" target="_blank" rel="noopener">Apri PDF</a>';
			}
			return '';
		}
	}
}
add_action( 'admin_init', 'sx_leads_table_bootstrap' );

StudioIndex_Report::boot();
