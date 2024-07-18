<?php

namespace PHPTerminalPluginsAuth;

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

        return $this;
    }

    public function getAccount($id)
    {
        $account = $this->authStore->findById($id);

        if ($account) {
            $account['id'] = $account['_id'];
            unset($account['_id']);
            unset($account['password']);

            return $account;
        }

        return false;
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
                if ($this->getSettings()['canResetPasswd'] &&
                    $password === $this->defaultPassword
                ) {
                    $password = $this->changePassword($account[0]);
                }

                if ($password) {
                    if ($this->passwordNeedsRehash($account[0]['password'])) {
                        $account[0]['password'] = $this->hashPassword($password);

                        $this->authStore->update($account);
                    }

                    $account[0]['id'] = $account[0]['_id'];
                    unset($account[0]['_id']);
                    unset($account[0]['password']);

                    return $account[0];
                }
            }
        }

        $this->hashPassword(rand());

        return false;
    }

    public function changePassword($account)
    {
        if (array_key_exists('id', $account)) {
            $account = $this->authStore->findById($account['id']);
        }

        if ($account) {
            $newPassword = $this->runChangePassword();

            if ($newPassword) {
                if ($this->checkPassword($newPassword, $account['password'])) {
                    \cli\line("");
                    \cli\line("%rNew password same as current password!%w" . PHP_EOL);

                    return false;
                } else {
                    $account['password']  = $this->hashPassword($newPassword);

                    $this->authStore->update($account);

                    return $newPassword;
                }
            }
        } else {
            $this->terminal->addResponse('Account with given ID not found!', 1);
        }

        return false;
    }

    protected function runChangePassword($initial = true)
    {
        $command = [];

        readline_callback_handler_install("", function () {});

        if ($initial) {
            \cli\line("");
            \cli\line("%bEnter new password%w" . PHP_EOL);
            \cli\out("%wNew Password: %w");
        } else {
            \cli\out("%wConfirm New Password: %w");
        }

        while (true) {
            $input = stream_get_contents(STDIN, 1);

            if (ord($input) == 10 || ord($input) == 13) {
                \cli\line("%r%w");

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
            if ($this->newPassword !== $this->confirmNewPassword) {
                \cli\line("%rNew and confirm password do not match! Try again...%w");

                $this->newPassword = null;
                $this->confirmNewPassword = null;

                return $this->runChangePassword($initial);
            }

            readline_callback_handler_remove();

            return $this->newPassword;
        }

        if ($this->newPasswordPromptCount >= 3 || $this->confirmNewPasswordPromptCount >= 3) {
            readline_callback_handler_remove();

            $this->terminal->addResponse('Incorrect Password! Try again...', 1);

            return false;
        }

        return $this->runChangePassword($initial);
    }

    protected function hashPassword(string $password)
    {
        return password_hash(
            $password,
            constant($this->terminal->config['plugins']['auth']['settings']['hash'] ?? $this->getSettings()['hash']) ?? PASSWORD_BCRYPT,
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
            constant($this->terminal->config['plugins']['auth']['settings']['hash'] ?? $this->getSettings()['hash']) ?? PASSWORD_BCRYPT,
            [
                'cost' => $this->terminal->config['plugins']['auth']['settings']['cost'] ?? 4
            ]
        );
    }

    public function updateSettings()
    {
        //
    }

    public function onInstall() : object
    {
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
                    ],
                    'permissions'   => [
                        'add'       => true,
                        'edit'      => true,
                        'remove'    => true
                    ]
                ]
            );
        }

        return $this;
    }

    public function onUninstall() : object
    {
        $this->authStore->deleteStore();

        return $this;
    }

    public function getSettings() : array
    {
        return
            [
                'cost'              => 4,
                'hash'              => 'PASSWORD_BCRYPT',
                'canResetPasswd'    => true
            ];
    }
}