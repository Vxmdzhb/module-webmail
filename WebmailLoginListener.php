<?php
declare(strict_types=1);

namespace AstrX\Webmail;

use AstrX\User\LoginListener;

/**
 * When the mail server shares the site's accounts (mailserver_is_local), the
 * login password is the IMAP password: keep it in the encrypted session so
 * the webmail page can connect without asking again. It survives a second
 * factor step; if that step fails, the session drops it.
 *
 * Otherwise nothing is kept: the site password would only be tried against a
 * mail server it doesn't belong to.
 */
final class WebmailLoginListener implements LoginListener
{
    public function __construct(
        private readonly WebmailService     $webmail,
        private readonly WebmailCredentials $credentials,
    ) {}

    public function passwordAccepted(string $password, bool $secondFactorPending): void
    {
        if ($this->webmail->mailserverIsLocal() && $password !== '') {
            $this->credentials->store($password);
        }
    }
}
