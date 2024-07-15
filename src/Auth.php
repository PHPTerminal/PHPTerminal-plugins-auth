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

    public function getDefaultPassword()
    {
        return $this->defaultPassword;
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

    public function changePassword()
    {
        //
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