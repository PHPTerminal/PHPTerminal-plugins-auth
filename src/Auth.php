<?php

namespace PHPTerminalAuth;

use PHPTerminal\Plugins;
use PHPTerminal\Terminal;
use SleekDB\Store;

class Auth extends Plugins
{
    protected $terminal;

    protected $authStore;

    protected $defaultPassword = 'admin';

    private $newPassword;

    private $confirmNewPassword;

    private $newPasswordPromptCount = 0;

    private $confirmNewPasswordPromptCount = 0;

    public function init(Terminal $terminal) : object
    {
        $this->terminal = $terminal;

        $this->authStore = new Store("auth", $this->terminal->databaseDirectory, $this->terminal->storeConfiguration);

        $accounts = $this->authStore->findAll();

        if (is_array($accounts) && count($accounts) === 0) {
            $admin = $this->authStore->updateOrInsert(
                [
                    '_id'       => 1,
                    'username'  => 'admin',
                    'password'  => $this->hashPassword($this->defaultPassword),
                    'profile'   => [
                        'full_name' => 'Administrator',
                        'email'     => 'email@yourdomain.com'
                    ]
                ]
            );
        }

        return $this;
    }

    public function newAccount()
    {
        //
    }

    public function attempt($username, $password)
    {
        return $this->checkAccount($username, $password);
    }

    protected function checkAccount($username, $password)
    {
        $account = $this->authStore->findBy(['username', '=', strtolower($username)]);

        if (count($account) === 1) {
            if ($this->checkPassword($password, $account[0]['password'])) {
                if ($this->getSettings()['canReset'] &&
                    $password === $this->defaultPassword
                ) {
                    $password = $this->changePassword($account);
                }

                if ($this->passwordNeedsRehash($account[0]['password'])) {
                    $account[0]['password'] = $this->hashPassword($password);

                    $this->authStore->update($account);
                }

                return [
                    'id'        => $account[0]['_id'],
                    'profile'   => $account[0]['profile']
                ];
            }
        }

        $this->hashPassword(rand());

        return false;
    }

    public function changePassword($account)
    {
        if (isset($accoun['id'])) {
            $account = $this->authStore->findById($account['id']);
        }

        if ($account) {
            $newPassword = $this->runChangePassword();

            $account[0]['password']  = $this->hashPassword($newPassword);

            $this->authStore->update($account[0]);

            return $newPassword;
        }

        return false;
    }

    protected function runChangePassword($initial = true)
    {
        $command = [];

        readline_callback_handler_install("", function () {});

        if ($initial) {
            \cli\line("%r%w");
            \cli\line("%bEnter new password\n");
            \cli\out("%wNew Password: ");
        } else {
            \cli\out("%wConfirm New Password: ");
        }

        while (true) {
            $input = stream_get_contents(STDIN, 1);

            if (ord($input) == 10) {
                // if (!$initial) {
                \cli\line("%r%w");
                // }
                break;
            } else if (ord($input) == 127) {
                if (count($command) === 0) {
                    continue;
                }
                array_pop($command);
                fwrite(STDOUT, chr(8));
                fwrite(STDOUT, "\033[0K");
            } else {
                $command[] = $input;

                fwrite(STDOUT, '*');
            }
        }

        $command = join($command);

        while (true) {
            if ($command !== '') {
                if ($initial) {
                    $this->newPassword = $command;
                } else {
                    $this->confirmNewPassword = $command;
                }
                if ($this->newPassword && !$this->confirmNewPassword) {
                    $initial = false;
                } else if (!$this->newPassword && $this->confirmNewPassword) {
                    $initial = true;
                } else if (($this->newPassword && $this->confirmNewPassword) &&
                           ($this->newPassword !== $this->confirmNewPassword)
                ) {
                    $initial = true;
                }
            } else {
                if ($initial) {
                    $this->newPasswordPromptCount++;
                } else {
                    $this->confirmNewPasswordPromptCount++;
                }
            }

            break;
        }

        if ($this->newPassword && $this->confirmNewPassword) {
            readline_callback_handler_remove();

            return $this->newPassword;
        }

        if ($this->newPasswordPromptCount >= 3 || $this->confirmNewPasswordPromptCount >= 3) {
            readline_callback_handler_remove();

            $this->terminal->addResponse('Incorrect Password! Try again...', 1);

            return true;
        }

        return $this->runChangePassword($initial);
    }

    protected function hashPassword(string $password)
    {
        return password_hash(
            $password,
            constant($this->terminal->config['plugins']['auth']['settings']['hash']) ?? PASSWORD_BCRYPT,
            [
                'cost' => $this->terminal->config['plugins']['auth']['settings']['cost'] ?? 4
            ]
        );
    }

    protected function checkPassword(string $password, string $hashedPassword)
    {
        return password_verify($password, $hashedPassword);
    }

    protected function passwordNeedsRehash(string $hashedPassword)
    {
        return password_needs_rehash(
            $hashedPassword,
            constant($this->terminal->config['plugins']['auth']['settings']['hash']) ?? PASSWORD_BCRYPT,
            [
                'cost' => $this->terminal->config['plugins']['auth']['settings']['cost'] ?? 4
            ]
        );
    }

    public function updateSettings()
    {
        //
    }

    public function getSettings() : array
    {
        return
            [
                'cost'      => 4,
                'hash'      => 'PASSWORD_BCRYPT',
                'canAdd'    => true,
                'canReset'  => true
            ];
    }
}