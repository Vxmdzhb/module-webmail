<?php
declare(strict_types=1);

namespace AstrX\Webmail\Controller;

use AstrX\Auth\Gate;
use AstrX\Csrf\CsrfHandler;
use AstrX\Http\Request;
use AstrX\Http\Response;
use AstrX\I18n\Translator;
use AstrX\Webmail\HtmlEmailSanitizer;
use AstrX\Webmail\WebmailCredentials;
use AstrX\Webmail\WebmailService;
use AstrX\Webmail\WebmailTrustedSenderRepository;
use AstrX\Page\Page;
use AstrX\Result\DiagnosticsCollector;
use AstrX\Result\Result;
use AstrX\Routing\UrlGenerator;
use AstrX\Session\FlashBag;
use AstrX\Session\PrgHandler;
use AstrX\Template\TemplateVars;
use AstrX\User\UserSession;
use AstrX\Kernel\AbstractController;
use AstrX\Webmail\WebmailPermission;

/**
 * Webmail — read, compose, send, manage emails.
 *
 * URL convention — all sub-params use query-string keys that do NOT conflict
 * with the routing 'page' key. Specifically 'pn' (page number) mirrors what
 * the news system uses.  The folder name is passed as 'folder'.
 *
 * GET parameters:
 *   folder=<name>      select IMAP folder (default: INBOX)
 *   pn=<n>             message list page number (default: 1)
 *   show=<n>           messages per page override (default: config value)
 *   sort=newest|oldest sort order (default: newest)
 *   uid=<n>            view a single message
 *   headers=1          view raw headers for ?uid=N
 *   compose=1          show compose form
 *   reply_uid=<n>      pre-fill compose as reply to message N
 *   forward_uid=<n>    pre-fill compose as a forward of message N
 *   draft_uid=<n>      edit draft N of the Drafts folder
 *   select=all         list view with every message ticked (no JavaScript)
 *   attachment=<n>     download attachment index N from ?uid=X&folder=Y
 *
 * POST actions (via PRG, all require CSRF):
 *   imap_login     store IMAP password in encrypted session
 *   send           send message (To/CC/BCC/Subject/Body)
 *   save_draft     save draft to Drafts folder
 *   delete         delete single message (uid + folder)
 *   delete_bulk    delete selected messages (uid[] + folder)
 *   move           move single message (uid + folder + target_folder)
 *   move_bulk      move selected messages (uid[] + folder + target_folder)
 *   mark_seen      mark single message read (uid + folder)
 *   mark_unseen    mark single message unread (uid + folder)
 *   mark_seen_bulk  mark selected messages read (uid[] + folder)
 *   mark_unseen_bulk mark selected messages unread (uid[] + folder)
 *   trust_sender   add sender to trusted list
 *   untrust_sender remove sender from trusted list
 *   disconnect     clear IMAP password from session
 */
final class WebmailController extends AbstractController
{
    private const FORM  = 'webmail';
    private const INBOX = 'INBOX';
    /** Login secret holding a compose form that could not be sent, to refill it. */
    private const COMPOSE_STASH = 'webmail.compose';

    public function __construct(
        DiagnosticsCollector                        $collector,
        private readonly TemplateVars      $ctx,
        private readonly Request                    $request,
        private readonly UserSession                $session,
        private readonly WebmailService             $webmail,
        private readonly WebmailCredentials         $credentials,
        private readonly WebmailTrustedSenderRepository $trustedSenders,
        private readonly HtmlEmailSanitizer         $sanitizer,
        private readonly Gate                       $gate,
        private readonly CsrfHandler                $csrf,
        private readonly PrgHandler                 $prg,
        private readonly FlashBag                   $flash,
        private readonly Page                       $page,
        private readonly UrlGenerator               $urlGen,
        private readonly Translator                 $t,
    ) {
        parent::__construct($collector);
    }

    // =========================================================================
    // Entry point
    // =========================================================================

    /** @return Result<mixed> */
    public function handle(): Result
    {
        if (!$this->session->isLoggedIn()) {
            Response::redirect($this->urlGen->toPage($this->t->t('WORDING_LOGIN')))
                ->send()->drainTo($this->collector);
            exit;
        }

        if ($this->gate->cannot(WebmailPermission::ACCESS)) {
            http_response_code(403);
            $this->ctx->set('webmail_forbidden', true);
            return $this->ok();
        }
        $this->ctx->set('webmail_forbidden', false);

        $selfUrl = $this->selfUrl();

        // ── PRG: handle POST mutations ────────────────────────────────────────
        $prgToken = $this->request->query()->get($this->prg->tokenQueryKey());
        if (is_string($prgToken) && $prgToken !== '') {
            $redirect = $this->processForm($prgToken, $selfUrl);
            Response::redirect($redirect)->send()->drainTo($this->collector);
            exit;
        }

        // ── Attachment download (GET, bypasses template entirely) ─────────────
        if ($this->request->query()->get('attachment') !== null) {
            $this->handleAttachmentDownload($selfUrl);
            return $this->ok();
        }

        // ── Require IMAP password ─────────────────────────────────────────────
        $imapPass = $this->credentials->password();
        if ($imapPass === '') {
            $this->buildLoginContext($selfUrl, imapError: false);
            return $this->ok();
        }

        // ── Connect to IMAP ───────────────────────────────────────────────────
        $mailbox  = $this->session->mailbox();
        $username = $this->session->username();
        $connectR = $this->webmail->connect($mailbox, $imapPass, $username);
        if (!$connectR->isOk()) {
            $connectR->drainTo($this->collector);
            $this->credentials->clear();
            $this->buildLoginContext($selfUrl, imapError: true);
            return $this->ok();
        }

        // ── Read GET params ───────────────────────────────────────────────────
        $folderRaw = $this->request->query()->get('folder');
        $folder   = is_string($folderRaw) ? $folderRaw : self::INBOX;
        $uidRaw   = $this->request->query()->get('uid');
        $uid      = is_int($uidRaw) ? $uidRaw : (is_numeric($uidRaw) ? (int)$uidRaw : 0);
        $pnRaw    = $this->request->query()->get('pn');
        $pn       = is_int($pnRaw) ? $pnRaw : (is_numeric($pnRaw) ? (int)$pnRaw : 1);
        $showRaw  = $this->request->query()->get('show');
        $show     = is_int($showRaw) ? $showRaw : (is_numeric($showRaw) ? (int)$showRaw : 0);
        $sort     = (is_scalar($vsort = $this->request->query()->get('sort') ?? 'newest') ? (string)$vsort : 'newest');
        $compose  = ($this->request->query()->get('compose') !== null);
        $replyUid = (is_numeric($vq_reply_uid = $this->request->query()->get('reply_uid')) ? (int)$vq_reply_uid : 0);
        $fwdUid   = (is_numeric($vq_fwd = $this->request->query()->get('forward_uid')) ? (int)$vq_fwd : 0);
        $draftUid = (is_numeric($vq_draft = $this->request->query()->get('draft_uid')) ? (int)$vq_draft : 0);
        $viewHdrs = ($this->request->query()->get('headers') !== null);
        $selectAll = $this->request->query()->get('select') === 'all';

        // ── Route to the appropriate view ─────────────────────────────────────
        if ($compose || $replyUid > 0 || $fwdUid > 0 || $draftUid > 0) {
            $this->buildComposeContext($selfUrl, $folder, $replyUid, $fwdUid, $draftUid);
        } elseif ($uid > 0 && $viewHdrs) {
            $this->buildRawHeadersContext($selfUrl, $folder, $uid, $pn);
        } elseif ($uid > 0) {
            $this->buildMessageContext($selfUrl, $folder, $uid, $pn);
        } else {
            $this->buildFolderContext($selfUrl, $folder, $pn, $show, $sort, $selectAll);
        }

        return $this->ok();
    }

    // =========================================================================
    // Form processing
    // =========================================================================

    private function processForm(string $prgToken, string $selfUrl): string
    {
        $posted = $this->prg->pull($prgToken) ?? [];
        $action = self::mStr($posted, 'action', '');

        // IMAP login. The user is already authenticated to the SITE here (so a
        // session-bound CSRF token is available), so this POST must carry CSRF
        // like every other webmail action — otherwise a cross-site POST could
        // plant an attacker-controlled IMAP password into the victim's webmail
        // session (login CSRF).
        if ($action === 'imap_login') {
            $csrfResult = $this->csrf->verify(self::FORM, self::mStr($posted, '_csrf', ''));
            if (!$csrfResult->isOk()) {
                $csrfResult->drainTo($this->collector);
                return $selfUrl;
            }
            $password = self::mStr($posted, 'imap_password', '');
            if ($password !== '') {
                $this->credentials->store($password);
            }
            return $selfUrl;
        }

        // All other actions require CSRF
        $csrfResult = $this->csrf->verify(self::FORM, self::mStr($posted, '_csrf', ''));
        if (!$csrfResult->isOk()) {
            $csrfResult->drainTo($this->collector);
            return $selfUrl;
        }

        if ($action === 'disconnect') {
            $this->credentials->clear();
            return $selfUrl;
        }
        $imapPass = $this->credentials->password();
        if ($imapPass === '') { return $selfUrl; }
        $connection = $this->webmail->connect($this->session->mailbox(), $imapPass, $this->session->username());
        if (!$connection->isOk()) {
            $connection->drainTo($this->collector);
            $this->credentials->clear();
            $this->flash->set('error', $this->t->t('webmail.login.error'));
            return $selfUrl;
        }

        $folderPRaw = $posted['folder'] ?? null;
        $folder = is_string($folderPRaw) ? $folderPRaw : self::INBOX;
        $uid    = self::mInt($posted, 'uid', 0);
        // Bulk: uid[] array of selected message UIDs
        $uidsRaw = is_array($posted['uid'] ?? null) ? $posted['uid'] : (array)($posted['uid'] ?? []);
        $uids   = array_map(fn($v): int => is_int($v) ? $v : (is_numeric($v) ? (int)$v : 0), $uidsRaw);
        $uids   = array_filter($uids, fn($u) => $u > 0);

        switch ($action) {
            case 'send':
                return $this->handleSend($posted, $folder);

            case 'save_draft':
                return $this->handleSaveDraft($posted, $folder);

            case 'delete':
            case 'delete_bulk':
            case 'move':
            case 'move_bulk':
                $selected = str_ends_with($action, '_bulk') ? $uids : ($uid > 0 ? [$uid] : []);
                if ($selected === []) {
                    $this->flash->set('info', $this->t->t('webmail.nothing_selected'));
                    return $this->selfUrl(['folder' => $folder]);
                }
                $move = str_starts_with($action, 'move');
                $target = trim(self::mStr($posted, 'target_folder', ''));
                if (!$move || $target !== '') {
                    foreach ($selected as $messageId) {
                        $result = $move ? $this->webmail->moveMessage($folder, $messageId, $target)
                            : $this->webmail->deleteMessage($folder, $messageId);
                        $result->drainTo($this->collector);
                        if (!$result->isOk()) {
                            $this->flash->set('error', $this->t->t('webmail.action_failed'));
                            return $this->selfUrl(['folder' => $folder]);
                        }
                    }
                    $key = match ($action) {
                        'delete' => 'webmail.message_deleted',
                        'delete_bulk' => 'webmail.messages_deleted',
                        'move' => 'webmail.message_moved',
                        default => 'webmail.messages_moved',
                    };
                    $this->flash->set('success', $this->t->t($key));
                }
                return $this->selfUrl(['folder' => $folder]);

            case 'mark_seen':
                if ($uid > 0) {
                    $this->webmail->setSeenFlag($folder, $uid, true)->drainTo($this->collector);
                }
                return $this->selfUrl(['folder' => $folder, 'uid' => $uid]);

            case 'mark_unseen':
                if ($uid > 0) {
                    $this->webmail->setSeenFlag($folder, $uid, false)->drainTo($this->collector);
                }
                return $this->selfUrl(['folder' => $folder, 'uid' => $uid]);

            case 'mark_seen_bulk':
            case 'mark_unseen_bulk':
                if ($uids === []) {
                    $this->flash->set('info', $this->t->t('webmail.nothing_selected'));
                    return $this->selfUrl(['folder' => $folder]);
                }
                $seen = $action === 'mark_seen_bulk';
                foreach ($uids as $u) {
                    $result = $this->webmail->setSeenFlag($folder, $u, $seen);
                    $result->drainTo($this->collector);
                    if (!$result->isOk()) {
                        $this->flash->set('error', $this->t->t('webmail.action_failed'));
                        return $this->selfUrl(['folder' => $folder]);
                    }
                }
                $this->flash->set('success', $this->t->t($seen ? 'webmail.marked_read' : 'webmail.marked_unread'));
                return $this->selfUrl(['folder' => $folder]);

            case 'trust_sender':
                $email = trim(self::mStr($posted, 'sender_email', ''));
                if ($email !== '') {
                    $this->trustedSenders->trust($this->session->userId(), $email)
                        ->drainTo($this->collector);
                    $this->flash->set('success', $this->t->t('webmail.sender_trusted'));
                }
                return $this->selfUrl(['folder' => $folder, 'uid' => $uid]);

            case 'untrust_sender':
                $email = trim(self::mStr($posted, 'sender_email', ''));
                if ($email !== '') {
                    $this->trustedSenders->untrust($this->session->userId(), $email)
                        ->drainTo($this->collector);
                    $this->flash->set('success', $this->t->t('webmail.sender_untrusted'));
                }
                return $this->selfUrl(['folder' => $folder, 'uid' => $uid]);

        }

        return $selfUrl;
    }

    // ── Send ──────────────────────────────────────────────────────────────────

    /**
     * The compose form's fields, as posted.
     *
     * @param array<string, mixed> $posted
     * @return array{to:string,cc:string,bcc:string,reply_to:string,subject:string,body:string,in_reply_to:string,priority:string,read_receipt:bool,draft_uid:int}
     */
    private static function composeFields(array $posted): array
    {
        $priority = self::mStr($posted, 'priority', 'normal');
        return [
            'to'           => trim(self::mStr($posted, 'to', '')),
            'cc'           => trim(self::mStr($posted, 'cc', '')),
            'bcc'          => trim(self::mStr($posted, 'bcc', '')),
            'reply_to'     => trim(self::mStr($posted, 'reply_to', '')),
            'subject'      => trim(self::mStr($posted, 'subject', '')),
            // Only trailing space: leading spaces can be part of the text.
            'body'         => rtrim(self::mStr($posted, 'body', '')),
            'in_reply_to'  => trim(self::mStr($posted, 'in_reply_to', '')),
            'priority'     => in_array($priority, ['high', 'normal', 'low'], true) ? $priority : 'normal',
            'read_receipt' => self::mStr($posted, 'read_receipt', '') === '1',
            'draft_uid'    => self::mInt($posted, 'draft_uid', 0),
        ];
    }

    /**
     * Keep a compose form that was sent back (a missing field, a refused
     * recipient, a server error), so the next page shows it as it was typed
     * instead of an empty form. It is kept among the login secrets, like the
     * IMAP password, and read once.
     *
     * @param array{to:string,cc:string,bcc:string,reply_to:string,subject:string,body:string,in_reply_to:string,priority:string,read_receipt:bool,draft_uid:int} $fields
     */
    private function stashCompose(array $fields): void
    {
        $this->session->storeSecret(self::COMPOSE_STASH, (string) json_encode($fields));
    }

    /** @return array<string, mixed>|null */
    private function pullCompose(): ?array
    {
        $raw = $this->session->secret(self::COMPOSE_STASH);
        if ($raw === '') { return null; }
        $this->session->storeSecret(self::COMPOSE_STASH, '');
        $fields = json_decode($raw, true);
        /** @var array<string, mixed>|null */
        return is_array($fields) ? $fields : null;
    }

    /** The name on the From line: the display name, or the username without one. */
    private function senderName(): string
    {
        $name = trim($this->session->displayName());
        return $name !== '' ? $name : $this->session->username();
    }

    /** @param array<string, mixed> $posted */
    private function handleSend(array $posted, string $folder): string
    {
        $f = self::composeFields($posted);

        if ($f['to'] === '' || $f['subject'] === '' || $f['body'] === '') {
            $this->flash->set('error', $this->t->t('webmail.compose_fields_required'));
            $this->stashCompose($f);
            return $this->selfUrl(['compose' => 1, 'folder' => $folder]);
        }

        $fromAddress = $this->webmail->resolveLocalPart(
            $this->session->mailbox(), $this->session->username()
        );
        $r = $this->webmail->sendMessage(
            fromAddress: $fromAddress,
            fromName:    $this->senderName(),
            toAddress:   $f['to'],
            subject:     $f['subject'],
            bodyText:    $f['body'],
            cc:          $f['cc'],
            bcc:         $f['bcc'],
            inReplyTo:   $f['in_reply_to'],
            priority:    $f['priority'],
            readReceipt: $f['read_receipt'],
            replyTo:     $f['reply_to'],
        );
        $r->drainTo($this->collector);

        if ($r->isOk()) {
            // A sent draft is no longer a draft.
            if ($f['draft_uid'] > 0) {
                $this->webmail->discardDraft($f['draft_uid'])->drainTo($this->collector);
            }
            $this->flash->set('success', $this->t->t('webmail.message_sent'));
            return $this->selfUrl(['folder' => $folder]);
        }

        $this->stashCompose($f);
        return $this->selfUrl(['compose' => 1, 'folder' => $folder]);
    }

    /**
     * Save the form to Drafts and keep editing it. Saving again replaces the
     * previous copy instead of piling up one draft per click.
     *
     * @param array<string, mixed> $posted
     */
    private function handleSaveDraft(array $posted, string $folder): string
    {
        $f = self::composeFields($posted);
        $fromAddress = $this->webmail->resolveLocalPart(
            $this->session->mailbox(), $this->session->username()
        );
        $r = $this->webmail->saveDraft(
            fromAddress: $fromAddress,
            fromName:    $this->senderName(),
            toAddress:   $f['to'],
            subject:     $f['subject'],
            bodyText:    $f['body'],
            cc:          $f['cc'],
            bcc:         $f['bcc'],
            inReplyTo:   $f['in_reply_to'],
            priority:    $f['priority'],
            replyTo:     $f['reply_to'],
        );
        $r->drainTo($this->collector);
        if (!$r->isOk()) {
            $this->stashCompose($f);
            return $this->selfUrl(['compose' => 1, 'folder' => $folder]);
        }
        if ($f['draft_uid'] > 0) {
            $this->webmail->discardDraft($f['draft_uid'])->drainTo($this->collector);
        }
        $this->flash->set('success', $this->t->t('webmail.draft_saved'));
        $newUid = $r->unwrap();
        if ($newUid > 0) {
            return $this->selfUrl(['draft_uid' => $newUid, 'folder' => $folder]);
        }
        // The server did not report the new draft's UID (no UIDPLUS): keep the
        // form as typed; saving again adds another copy.
        $f['draft_uid'] = 0;
        $this->stashCompose($f);
        return $this->selfUrl(['compose' => 1, 'folder' => $folder]);
    }

    // ── Attachment download ───────────────────────────────────────────────────

    private function handleAttachmentDownload(string $selfUrl): void
    {
        $imapPass = $this->credentials->password();
        if ($imapPass === '') { return; }

        $folderQRaw = $this->request->query()->get('folder');
        $folder = is_string($folderQRaw) ? $folderQRaw : self::INBOX;
        $uid    = (is_numeric($vq_uid = $this->request->query()->get('uid')) ? (int)$vq_uid : 0);
        $index  = (is_numeric($vq_attachment = $this->request->query()->get('attachment')) ? (int)$vq_attachment : 0);
        if ($uid <= 0) { return; }

        $connection = $this->webmail->connect($this->session->mailbox(), $imapPass, $this->session->username());
        if (!$connection->isOk()) {
            $connection->drainTo($this->collector);
            $this->credentials->clear();
            $this->buildLoginContext($selfUrl, imapError: true);
            return;
        }
        $r = $this->webmail->getAttachment($folder, $uid, $index);
        if (!$r->isOk()) { $r->drainTo($this->collector); return; }

        $att      = $r->unwrap();
        $safeName = preg_replace('/[^a-zA-Z0-9._-]/', '_', $att['name']);

        if (!headers_sent()) {
            header('Content-Type: '        . ($att['content_type'] ?: 'application/octet-stream'));
            header('Content-Disposition: attachment; filename="' . $safeName . '"');
            header('Content-Length: '      . strlen($att['data']));
            header('Cache-Control: private, no-cache');
            header('X-Content-Type-Options: nosniff');
        }
        echo $att['data'];
        exit;
    }

    // =========================================================================
    // Context builders
    // =========================================================================

    private function buildLoginContext(string $selfUrl, bool $imapError): void
    {
        $this->ctx->set('webmail_view',         'login');
        $this->ctx->set('webmail_view_login',    true);
        $this->ctx->set('webmail_view_list',     false);
        $this->ctx->set('webmail_view_message',  false);
        $this->ctx->set('webmail_view_compose',  false);
        $this->ctx->set('webmail_view_headers',  false);
        if ($imapError) {
            $this->flash->set('error', $this->t->t('webmail.login.error'));
        }
        $this->ctx->set('webmail_login_account', $this->t->t('webmail.login.account', [
            'account' => $this->webmail->loginName($this->session->mailbox(), $this->session->username()),
        ]));
        $this->ctx->set('prg_id',                $this->prg->createId($selfUrl));
        $this->ctx->set('base_url',              $selfUrl);
        // CSRF token for the IMAP-login form. The user already holds a
        // site session here, so a session-bound token is available pre-IMAP-auth.
        $this->ctx->set('csrf_token',            $this->csrf->generate(self::FORM));
        $this->setI18n();
    }

    private function buildFolderContext(
        string $selfUrl,
        string $folder,
        int    $pn,
        int    $show,
        string $sort,
        bool   $selectAll = false,
    ): void {
        $folders = $this->getFolders($folder);
        $listR   = $this->webmail->listMessages($folder, $pn, $show, $sort === 'oldest');
        $listR->drainTo($this->collector);
        $list = $listR->isOk() ? $listR->unwrap()
            : ['messages' => [], 'total' => 0, 'pages' => 1, 'page' => 1, 'per_page' => 25];

        // In Sent and Drafts the other party is the recipient: the sender is
        // always you.
        $type     = $this->specialType($folders, $folder);
        $outgoing = in_array($type, ['sent', 'drafts'], true);

        $csrfToken = $this->csrf->generate(self::FORM);
        $prgId     = $this->prg->createId($selfUrl);

        $effectivePerPage = $show > 0 ? $show : $list['per_page'];
        $msgFrom = $list['total'] > 0 ? ($list['page'] - 1) * $effectivePerPage + 1 : 0;
        $msgTo   = min($list['page'] * $effectivePerPage, $list['total']);

        // Build pagination URLs preserving all sub-params
        // Use 'pn' not 'page' to avoid conflicting with the routing 'page' key
        $baseParams = array_filter(['folder' => $folder,
                                    'show' => $show ?: null,
                                    'sort' => $sort !== 'newest' ? $sort : null]);
        $prevUrl = $this->selfUrl(array_merge($baseParams, ['pn' => $list['page'] - 1]));
        $nextUrl = $this->selfUrl(array_merge($baseParams, ['pn' => $list['page'] + 1]));
        // Select all without JavaScript: the page again, with every box ticked.
        $pageParams = array_merge($baseParams, $list['page'] > 1 ? ['pn' => $list['page']] : []);
        $selectAllUrl  = $this->selfUrl(array_merge($pageParams, ['select' => 'all']));
        $selectNoneUrl = $this->selfUrl($pageParams);

        // Move-to options for bulk bar
        $moveOptions = [];
        foreach ($folders as $f) {
            if ($f['name'] !== $folder) {
                $moveOptions[] = ['name' => $f['name'], 'display' => $f['display']];
            }
        }

        // A GET form replaces its action's query string at submission.
        parse_str((string) parse_url($selfUrl, PHP_URL_QUERY), $routing);
        $fields = [];
        foreach ($routing as $name => $value) {
            if (is_string($value)) { $fields[] = ['name' => $name, 'value' => $value]; }
        }
        $this->ctx->set('filter_route', $fields);
        $this->ctx->set('webmail_view',          'list');
        $this->ctx->set('webmail_view_login',     false);
        $this->ctx->set('webmail_view_list',      true);
        $this->ctx->set('webmail_view_message',   false);
        $this->ctx->set('webmail_view_compose',   false);
        $this->ctx->set('webmail_view_headers',   false);
        $this->ctx->set('folders',                $folders);
        $this->ctx->set('current_folder',         $folder);
        $this->ctx->set('mail_list',              $this->decorateMessages($list['messages'], $folder, $outgoing, $selectAll, $type === 'drafts'));
        $this->ctx->set('has_mail_list',          $list['messages'] !== []);
        $this->ctx->set('label_party',            $this->t->t($outgoing ? 'webmail.to' : 'webmail.from'));
        $this->ctx->set('all_selected',           $selectAll);
        $this->ctx->set('select_all_url',         $selectAllUrl);
        $this->ctx->set('select_none_url',        $selectNoneUrl);
        $this->ctx->set('label_select_none',      $this->t->t('webmail.select_none'));
        $this->ctx->set('label_range',            $this->t->t('webmail.range', [
            'from' => (string) $msgFrom, 'to' => (string) $msgTo, 'total' => (string) $list['total'],
        ]));
        $this->ctx->set('msg_total',              $list['total']);
        $this->ctx->set('msg_pages',              $list['pages']);
        $this->ctx->set('msg_page',               $list['page']);
        $this->ctx->set('msg_from',               $msgFrom);
        $this->ctx->set('msg_to',                 $msgTo);
        $this->ctx->set('has_prev',               $list['page'] > 1);
        $this->ctx->set('has_next',               $list['page'] < $list['pages']);
        $this->ctx->set('prev_url',               $prevUrl);
        $this->ctx->set('next_url',               $nextUrl);
        $this->ctx->set('move_options',           $moveOptions);
        $this->ctx->set('sort_newest',            $sort !== 'oldest');
        $this->ctx->set('sort_oldest',            $sort === 'oldest');
        $this->ctx->set('current_per_page',       $effectivePerPage);
        $this->ctx->set('current_sort',           $sort);
        $this->ctx->set('filter_action',          $selfUrl);
        $this->ctx->set('csrf_token',             $csrfToken);
        $this->ctx->set('prg_id',                 $prgId);
        $this->ctx->set('base_url',               $selfUrl);
        $this->setShared($folder);
    }

    private function buildMessageContext(
        string $selfUrl,
        string $folder,
        int    $uid,
        int    $pn,
    ): void {
        $folders   = $this->getFolders($folder);
        $msgR      = $this->webmail->getMessage($folder, $uid);
        $msgR->drainTo($this->collector);
        $message   = $msgR->isOk() ? $msgR->unwrap() : null;
        $csrfToken = $this->csrf->generate(self::FORM);
        $prgId     = $this->prg->createId($selfUrl);

        $senderEmail   = '';
        $senderTrusted = false;
        if ($message !== null) {
            $senderEmail = $this->extractEmailAddress((is_scalar($message['from'] ?? null) ? (string)$message['from'] : ''));
            if ($senderEmail !== '') {
                $trustR = $this->trustedSenders->isTrusted($this->session->userId(), $senderEmail);
                $senderTrusted = $trustR->isOk() && $trustR->unwrap();
            }
        }

        $safeHtml = '';
        $hasHtml  = false;
        if ($message !== null && is_string($message['body_html'] ?? null) && $message['body_html'] !== '') {
            $hasHtml  = true;
            $safeHtml = $this->sanitizer->sanitise((string)$message['body_html'], $senderTrusted);
        }

        $attachments = [];
        $msgAtts = is_array($message['attachments'] ?? null) ? $message['attachments'] : [];
        foreach ($msgAtts as $idx => $att) {
            /** @var array<string,mixed> $att */
            $attachments[] = [
                'index'        => $idx,
                'name'         => is_scalar($att['name'] ?? null) ? (string)$att['name'] : '',
                'content_type' => is_scalar($att['content_type'] ?? null) ? (string)$att['content_type'] : '',
                'size_fmt'     => $this->formatBytes(is_int($att['size'] ?? null) ? (int)$att['size'] : 0),
                'download_url' => $this->selfUrl([
                                                                        'folder' => $folder, 'uid' => $uid, 'attachment' => $idx,
                                                                    ]),
            ];
        }

        $moveOptions = [];
        foreach ($this->getFolderList() as $f) {
            if ($f['name'] !== $folder) {
                $moveOptions[] = ['name' => $f['name'], 'display' => $f['display']];
            }
        }

        $backUrl     = $this->selfUrl(['folder' => $folder, 'pn' => $pn]);
        $headersUrl  = $this->selfUrl(['folder' => $folder, 'uid' => $uid, 'headers' => 1, 'pn' => $pn]);
        $replyUrl    = $this->selfUrl(['reply_uid' => $uid, 'folder' => $folder]);
        $forwardUrl  = $this->selfUrl(['forward_uid' => $uid, 'folder' => $folder]);
        $isDraft     = $this->specialType($folders, $folder) === 'drafts';
        // The plain-text part is shown when there is one, and then the HTML
        // part (and its images) is not shown at all.
        $htmlShown   = $hasHtml && !(is_string($message['body_text'] ?? null) && $message['body_text'] !== '');

        $this->ctx->set('webmail_view',          'message');
        $this->ctx->set('webmail_view_login',     false);
        $this->ctx->set('webmail_view_list',      false);
        $this->ctx->set('webmail_view_message',   true);
        $this->ctx->set('webmail_view_compose',   false);
        $this->ctx->set('webmail_view_headers',   false);
        $this->ctx->set('folders',                $folders);
        $this->ctx->set('current_folder',         $folder);
        $this->ctx->set('message',                $message);
        $this->ctx->set('message_found',          $message !== null);
        $this->ctx->set('body_html_safe',         $safeHtml);
        $this->ctx->set('has_html_body',          $hasHtml);
        $this->ctx->set('images_blocked',         $htmlShown && !$senderTrusted);
        $this->ctx->set('sender_email',           $senderEmail);
        $this->ctx->set('sender_trusted',         $htmlShown && $senderTrusted);
        $this->ctx->set('attachments',            $attachments);
        $this->ctx->set('has_attachments',        $attachments !== []);
        $this->ctx->set('move_options',           $moveOptions);
        $this->ctx->set('msg_uid',                $uid);
        $this->ctx->set('msg_folder',             $folder);
        $this->ctx->set('msg_pn',                 $pn);
        $this->ctx->set('back_url',               $backUrl);
        $this->ctx->set('headers_url',            $headersUrl);
        $this->ctx->set('reply_url',              $replyUrl);
        $this->ctx->set('forward_url',            $forwardUrl);
        $this->ctx->set('is_draft',               $isDraft);
        $this->ctx->set('edit_draft_url',         $this->selfUrl(['draft_uid' => $uid, 'folder' => $folder]));
        $this->ctx->set('csrf_token',             $csrfToken);
        $this->ctx->set('prg_id',                 $prgId);
        $this->ctx->set('base_url',               $selfUrl);
        $this->setShared($folder);
    }

    private function buildRawHeadersContext(
        string $selfUrl,
        string $folder,
        int    $uid,
        int    $pn,
    ): void {
        $folders   = $this->getFolders($folder);
        $rawR      = $this->webmail->fetchRawHeaders($folder, $uid);
        $rawR->drainTo($this->collector);
        $rawHeaders = $rawR->isOk() ? $rawR->unwrap() : $this->t->t('webmail.raw_headers_failed');
        $csrfToken  = $this->csrf->generate(self::FORM);
        $prgId      = $this->prg->createId($selfUrl);

        $backUrl = $this->selfUrl(['folder' => $folder, 'uid' => $uid, 'pn' => $pn]);

        $this->ctx->set('webmail_view',          'headers');
        $this->ctx->set('webmail_view_login',     false);
        $this->ctx->set('webmail_view_list',      false);
        $this->ctx->set('webmail_view_message',   false);
        $this->ctx->set('webmail_view_compose',   false);
        $this->ctx->set('webmail_view_headers',   true);
        $this->ctx->set('folders',                $folders);
        $this->ctx->set('current_folder',         $folder);
        $this->ctx->set('raw_headers',            $rawHeaders);
        $this->ctx->set('msg_uid',                $uid);
        $this->ctx->set('msg_folder',             $folder);
        $this->ctx->set('back_url',               $backUrl);
        $this->ctx->set('csrf_token',             $csrfToken);
        $this->ctx->set('prg_id',                 $prgId);
        $this->ctx->set('base_url',               $selfUrl);
        $this->setShared($folder);
    }

    private function buildComposeContext(string $selfUrl, string $folder, int $replyUid, int $fwdUid = 0, int $draftUid = 0): void
    {
        $folders   = $this->getFolders($folder);
        $csrfToken = $this->csrf->generate(self::FORM);
        $prgId     = $this->prg->createId($selfUrl);

        $f = [
            'to' => '', 'cc' => '', 'bcc' => '', 'reply_to' => '', 'subject' => '', 'body' => '',
            'in_reply_to' => '', 'priority' => 'normal', 'read_receipt' => false, 'draft_uid' => 0,
        ];
        $note = '';

        $stash = $this->pullCompose();
        if ($stash !== null) {
            // The form as it was sent back.
            foreach ($f as $key => $default) {
                $v = $stash[$key] ?? $default;
                $f[$key] = is_bool($default) ? (bool) $v : (is_int($default) ? (is_numeric($v) ? (int) $v : 0) : (is_scalar($v) ? (string) $v : ''));
            }
        } elseif ($draftUid > 0) {
            $msgR = $this->webmail->getMessage($this->webmail->draftsFolder(), $draftUid);
            $msgR->drainTo($this->collector);
            if ($msgR->isOk()) {
                /** @var array<string,mixed> $msg */
                $msg = $msgR->unwrap();
                $f['to']          = self::field($msg, 'to');
                $f['cc']          = self::field($msg, 'cc');
                $f['bcc']         = self::field($msg, 'bcc');
                $f['reply_to']    = self::field($msg, 'reply_to');
                $f['subject']     = self::field($msg, 'subject') === '(no subject)' ? '' : self::field($msg, 'subject');
                $f['body']        = rtrim(self::field($msg, 'body_text'));
                $f['draft_uid']   = $draftUid;
            }
        } elseif ($replyUid > 0 || $fwdUid > 0) {
            $msgR = $this->webmail->getMessage($folder, $replyUid > 0 ? $replyUid : $fwdUid);
            $msgR->drainTo($this->collector);
            if ($msgR->isOk()) {
                /** @var array<string,mixed> $msg */
                $msg     = $msgR->unwrap();
                $from    = self::field($msg, 'from');
                $subject = self::field($msg, 'subject');
                $date    = self::field($msg, 'date');
                $body    = rtrim(self::field($msg, 'body_text'));
                if ($replyUid > 0) {
                    // Reply to where the sender asked (Reply-To), and from your
                    // own sent mail, to the people you wrote to.
                    $outgoing = in_array($this->specialType($folders, $folder), ['sent', 'drafts'], true);
                    $f['to'] = $outgoing ? self::field($msg, 'to')
                        : (self::field($msg, 'reply_to') !== '' ? self::field($msg, 'reply_to') : $from);
                    $f['subject']     = 'Re: ' . (preg_replace('/^(?:\s*re\s*:\s*)+/i', '', $subject) ?? $subject);
                    $f['in_reply_to'] = self::field($msg, 'message_id');
                    if ($body !== '') {
                        $f['body'] = "\n\n" . $this->t->t('webmail.reply_quote', ['date' => $date, 'sender' => $from]) . "\n"
                            . implode("\n", array_map(static fn (string $l): string => '> ' . $l, explode("\n", $body)));
                    }
                } else {
                    $f['subject'] = 'Fwd: ' . (preg_replace('/^(?:\s*fwd?\s*:\s*)+/i', '', $subject) ?? $subject);
                    $f['body'] = "\n\n" . $this->t->t('webmail.forward_separator') . "\n"
                        . $this->t->t('webmail.from') . ': ' . $from . "\n"
                        . $this->t->t('webmail.date') . ': ' . $date . "\n"
                        . $this->t->t('webmail.subject') . ': ' . $subject . "\n"
                        . $this->t->t('webmail.to') . ': ' . self::field($msg, 'to') . "\n\n"
                        . $body;
                    if (is_array($msg['attachments'] ?? null) && $msg['attachments'] !== []) {
                        $note = $this->t->t('webmail.forward_no_attachments');
                    }
                }
            }
        }

        $this->ctx->set('webmail_view',          'compose');
        $this->ctx->set('webmail_view_login',     false);
        $this->ctx->set('webmail_view_list',      false);
        $this->ctx->set('webmail_view_message',   false);
        $this->ctx->set('webmail_view_compose',   true);
        $this->ctx->set('webmail_view_headers',   false);
        $this->ctx->set('folders',                $folders);
        $this->ctx->set('current_folder',         $folder);
        $this->ctx->set('compose_to',             $f['to']);
        $this->ctx->set('compose_cc',             $f['cc']);
        $this->ctx->set('compose_bcc',            $f['bcc']);
        $this->ctx->set('compose_reply_to',       $f['reply_to']);
        $this->ctx->set('compose_subject',        $f['subject']);
        $this->ctx->set('compose_body',           $f['body']);
        $this->ctx->set('compose_in_reply_to',    $f['in_reply_to']);
        $this->ctx->set('compose_draft_uid',      $f['draft_uid']);
        $this->ctx->set('priority_high',          $f['priority'] === 'high');
        $this->ctx->set('priority_normal',        $f['priority'] === 'normal');
        $this->ctx->set('priority_low',           $f['priority'] === 'low');
        $this->ctx->set('compose_read_receipt',   $f['read_receipt']);
        $this->ctx->set('compose_note',           $note);
        $this->ctx->set('has_compose_note',       $note !== '');
        // The address the message will be sent from, exactly as sendMessage() builds it.
        $localPart = $this->webmail->resolveLocalPart($this->session->mailbox(), $this->session->username());
        $this->ctx->set('user_mailbox',           $this->senderName() . ' <' . (str_contains($localPart, '@') ? $localPart : $localPart . '@' . $this->webmail->mailDomain()) . '>');
        $this->ctx->set('back_url',               $this->selfUrl(['folder' => $folder]));
        $this->ctx->set('csrf_token',             $csrfToken);
        $this->ctx->set('prg_id',                 $prgId);
        $this->ctx->set('base_url',               $selfUrl);
        $this->setShared($folder);
    }

    /** @param array<string,mixed> $msg */
    private static function field(array $msg, string $key): string
    {
        $v = $msg[$key] ?? '';
        return is_scalar($v) ? (string) $v : '';
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /** @param array<string,scalar> $query */
    private function selfUrl(array $query = []): string
    {
        $urlId = $this->page->i18n
            ? $this->t->t($this->page->urlId, fallback: $this->page->urlId)
            : $this->page->urlId;
        return $this->urlGen->toPage($urlId, $query);
    }

    /** @return list<array<string, mixed>> */
    private function getFolders(string $currentFolder): array
    {
        $r = $this->webmail->getFolders();
        if (!$r->isOk()) { return []; }
        return array_map(function ($f) use ($currentFolder) {
            $f['display']    = $this->folderLabel($f['name'], $f['display'], $f['special_type']);
            $f['url']        = $this->selfUrl(['folder' => $f['name']]);
            $f['is_current'] = $f['name'] === $currentFolder;
            $f['has_unseen'] = $f['unseen'] > 0;
            return $f;
        }, $r->unwrap());
    }

    /** @return list<array{name:string,display:string}> */
    private function getFolderList(): array
    {
        $r = $this->webmail->getFolders();
        return $r->isOk()
            ? array_map(fn($f) => ['name' => $f['name'], 'display' => $this->folderLabel($f['name'], $f['display'], $f['special_type'])], $r->unwrap())
            : [];
    }

    /** The folder's name in the page's language when it is a standard one. */
    private function folderLabel(string $name, string $display, string $specialType): string
    {
        $key = $name === self::INBOX ? 'webmail.inbox' : ($specialType !== '' ? 'webmail.folder.' . $specialType : '');
        return $key !== '' ? $this->t->t($key, fallback: $display) : $display;
    }

    /**
     * 'sent', 'drafts', 'trash', 'inbox' or '' for the folder.
     *
     * @param list<array<string, mixed>> $folders
     */
    private function specialType(array $folders, string $folder): string
    {
        foreach ($folders as $f) {
            if (($f['name'] ?? null) === $folder) {
                return is_string($f['special_type'] ?? null) ? $f['special_type'] : '';
            }
        }
        return match ($folder) {
            $this->webmail->sentFolder()   => 'sent',
            $this->webmail->draftsFolder() => 'drafts',
            default                        => '',
        };
    }

    /**
     * @param list<array{uid:int,flags:list<string>,subject:string,from_display:string,to_display:string,date_str:string,date_ts:int,seen:bool}> $messages
     * @return list<array<string,mixed>>
     */
    private function decorateMessages(array $messages, string $folder, bool $outgoing = false, bool $checked = false, bool $drafts = false): array
    {
        $even = false;
        return array_map(function ($m) use ($folder, $outgoing, $checked, $drafts, &$even) {
            // A draft opens in the editor, like in any mail client.
            $m['view_url']  = $this->selfUrl($drafts ? ['draft_uid' => $m['uid'], 'folder' => $folder]
                                                     : ['folder' => $folder, 'uid' => $m['uid']]);
            $m['party']     = $outgoing ? $m['to_display'] : $m['from_display'];
            $m['checked']   = $checked;
            // The site's times are UTC; say so, since the message itself shows
            // the sender's own offset.
            $m['date_fmt']  = $m['date_ts'] > 0 ? date('d M Y H:i', $m['date_ts']) . ' UTC' : $m['date_str'];
            $m['unread']    = !$m['seen'];
            $m['row_even']  = $even;
            $even           = !$even;
            return $m;
        }, $messages);
    }

    private function extractEmailAddress(string $from): string
    {
        if (preg_match('/<([^>]+)>/', $from, $m)) { return strtolower(trim($m[1])); }
        $bare = trim($from);
        return str_contains($bare, '@') ? strtolower($bare) : '';
    }

    private function formatBytes(int $bytes): string
    {
        if ($bytes < 1024)    { return $bytes . ' B'; }
        if ($bytes < 1048576) { return round($bytes / 1024, 1) . ' KB'; }
        return round($bytes / 1048576, 1) . ' MB';
    }

    /** What every signed-in view shows: the labels, and the sidebar's Compose link. */
    private function setShared(string $folder): void
    {
        $this->ctx->set('compose_url', $this->selfUrl(['compose' => 1, 'folder' => $folder]));
        $this->setI18n();
    }

    private function setI18n(): void
    {
        $map = [
            'webmail_heading'                => 'webmail.heading',
            'webmail_login_heading'          => 'webmail.login.heading',
            'webmail_login_body'             => 'webmail.login.body',
            'webmail_login_password'         => 'webmail.login.password',
            'webmail_login_btn'              => 'webmail.login.btn',
            'webmail_compose_heading'        => 'webmail.compose.heading',
            'webmail_compose_from'           => 'webmail.compose.from',
            'webmail_compose_to'             => 'webmail.compose.to',
            'webmail_compose_cc'             => 'webmail.compose.cc',
            'webmail_compose_bcc'            => 'webmail.compose.bcc',
            'webmail_compose_subject'        => 'webmail.compose.subject',
            'webmail_compose_body'           => 'webmail.compose.body',
            'webmail_compose_send'           => 'webmail.compose.send',
            'webmail_compose_save_draft'     => 'webmail.compose.save_draft',
            'webmail_compose_cancel'         => 'webmail.compose.cancel',
            'label_folders'                  => 'webmail.folders',
            'label_from'                     => 'webmail.from',
            'label_to'                       => 'webmail.to',
            'label_subject'                  => 'webmail.subject',
            'label_date'                     => 'webmail.date',
            'label_no_messages'              => 'webmail.no_messages',
            'label_attachments'              => 'webmail.attachments',
            'label_download'                 => 'webmail.download',
            'label_total'                    => 'webmail.total',
            'label_viewing'                  => 'webmail.viewing',
            'label_transform'                => 'webmail.transform',
            'label_move_selected'            => 'webmail.move_selected',
            'label_sort_newest'              => 'webmail.sort_newest',
            'label_sort_oldest'              => 'webmail.sort_oldest',
            'label_sort'                     => 'webmail.sort',
            'label_show'                     => 'webmail.show',
            'label_per_page'                 => 'webmail.per_page',
            'label_view_headers'             => 'webmail.view_headers',
            'label_raw_headers_heading'      => 'webmail.raw_headers_heading',
            'btn_mark_read_bulk'             => 'webmail.btn_mark_read_bulk',
            'btn_mark_unread_bulk'           => 'webmail.btn_mark_unread_bulk',
            'btn_delete_bulk'                => 'webmail.btn_delete_bulk',
            'btn_move_bulk'                  => 'webmail.btn_move_bulk',
            'btn_forward'                    => 'webmail.btn_forward',
            'label_priority'                 => 'webmail.compose.priority',
            'label_priority_high'            => 'webmail.compose.priority_high',
            'label_priority_normal'          => 'webmail.compose.priority_normal',
            'label_priority_low'             => 'webmail.compose.priority_low',
            'label_read_receipt'             => 'webmail.compose.read_receipt',
            'label_reply_to_field'           => 'webmail.compose.reply_to',
            'btn_compose'                    => 'webmail.btn_compose',
            'btn_reply'                      => 'webmail.btn_reply',
            'btn_delete'                     => 'webmail.btn_delete',
            'btn_move'                       => 'webmail.btn_move',
            'btn_mark_read'                  => 'webmail.btn_mark_read',
            'btn_mark_unread'                => 'webmail.btn_mark_unread',
            'btn_back'                       => 'webmail.btn_back',
            'btn_disconnect'                 => 'webmail.btn_disconnect',
            'label_move_to'                  => 'webmail.move_to',
            'label_prev'                     => 'webmail.prev',
            'label_next'                     => 'webmail.next',
            'label_page'                     => 'webmail.page',
            'label_of'                       => 'webmail.of',
            'label_images_blocked'           => 'webmail.images_blocked',
            'label_trust_sender'             => 'webmail.trust_sender',
            'label_untrust_sender'           => 'webmail.untrust_sender',
            'label_sender_trusted'           => 'webmail.sender_trusted_notice',
            'label_select_all'               => 'webmail.select_all',
            'label_cc'                       => 'webmail.compose.cc',
            'label_reply_to'                 => 'webmail.compose.reply_to',
            'label_optional'                 => 'webmail.compose.optional',
            'label_message_not_found'        => 'webmail.message_not_found',
            'btn_edit_draft'                 => 'webmail.btn_edit_draft',
            'label_go'                       => 'webmail.go',
        ];
        foreach ($map as $ctxKey => $langKey) {
            $this->ctx->set($ctxKey, $this->t->t($langKey, fallback: $ctxKey));
        }
    }
}
