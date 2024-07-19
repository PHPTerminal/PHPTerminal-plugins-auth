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

    public function getAccountById($id)
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

    public function getAccountByUsername($username)
    {
        $account = $this->authStore->findBy(['username', '=', strtolower($username)]);

        if (count($account) === 1) {
            $account[0]['id'] = $account[0]['_id'];
            unset($account[0]['_id']);
            unset($account[0]['password']);

            return $account[0];
        }

        return false;
    }

    public function getAllAccounts()
    {
        $accounts = $this->authStore->findAll();

        if ($accounts && count($accounts) > 0) {
            foreach ($accounts as $accountKey => &$account) {
                $account['id'] = $account['_id'];
                unset($account['_id']);
                unset($account['password']);
                $account['full_name'] = $account['profile']['full_name'];
                $account['email'] = $account['profile']['email'];
                unset($account['profile']);
                $account['permissions_enable'] = $account['permissions']['enable'];
                $account['permissions_config'] = $account['permissions']['config'];
                unset($account['permissions']);

                $account = array_replace(array_flip(array('id', 'username', 'full_name', 'email', 'permissions_enable', 'permissions_config')), $account);
            }

            return $accounts;
        }

        return false;
    }

    public function addAccount(array $data)
    {
        if (!isset($data['username']) ||
            (isset($data['username']) && $data['username'] === '')
        ) {
            \cli\line("");
            \cli\line('%rPlease provide username%w');
            \cli\line("");

            return false;
        }

        $account = $this->authStore->findBy(['username', '=', strtolower($data['username'])]);

        if ($account) {
            \cli\line("");
            \cli\line('%rAccount with username : ' . $data['username'] . ' already exists!%w');
            \cli\line("");

            return false;
        }

        if (!isset($data['password']) ||
            (isset($data['password']) && $data['password'] === '')
        ) {
            $data['password'] = $this->defaultPassword;
        }

        $newAccount['username'] = $data['username'];
        $newAccount['password'] = $this->hashPassword($data['password']);
        $newAccount['profile']['full_name'] = 'New Account';
        if (isset($data['full_name'])) {
            $newAccount['profile']['full_name'] = $data['full_name'];
        }
        $newAccount['profile']['email'] = 'email@yourdomain.com';
        if (isset($data['email'])) {
            $newAccount['profile']['email'] = $data['email'];
        }
        $newAccount['permissions']['enable'] = true;
        if (isset($data['permissions']['enable'])) {
            $newAccount['permissions']['enable'] = (bool) $data['permissions']['enable'];
        }
        $newAccount['permissions']['config'] = true;
        if (isset($data['permissions']['config'])) {
            $newAccount['permissions']['config'] = (bool) $data['permissions']['config'];
        }

        if ($this->authStore->insert($newAccount)) {
            return true;
        }

        return false;
    }

    public function updateAccount(array $data)
    {
        if (!isset($data['username']) ||
            (isset($data['username']) && $data['username'] === '')
        ) {
            \cli\line("");
            \cli\line('%rPlease provide username%w');
            \cli\line("");

            return false;
        }

        $account = $this->authStore->findBy(['username', '=', strtolower($data['username'])]);

        if (!$account) {
            \cli\line("");
            \cli\line('%rAccount with username : ' . $data['username'] . ' does not exist!%w');
            \cli\line("");

            return false;
        }

        if (isset($data['full_name'])) {
            $account[0]['profile']['full_name'] = $data['full_name'];
        }

        if (isset($data['email'])) {
            $account[0]['profile']['email'] = $data['email'];
        }

        if (isset($data['permissions']['enable'])) {
            $account[0]['permissions']['enable'] = (bool) $data['permissions']['enable'];
        }

        if (isset($data['permissions']['config'])) {
            $account[0]['permissions']['config'] = (bool) $data['permissions']['config'];
        }

        if ($this->authStore->update($account[0])) {
            return true;
        }

        return false;

    }

    public function removeAccount($id)
    {
        $account = $this->getAccountById($id);

        if ($account) {
            return $this->authStore->deleteById($id);
        }

        return false;
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
                        'enable'    => true,
                        'config'    => true
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

    public function updateSettings(array $data)
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
}