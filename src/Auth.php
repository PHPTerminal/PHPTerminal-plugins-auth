<?php

namespace PHPTerminalAuth;

use PHPTerminal\PluginsInterface;
use PHPTerminal\Terminal;
use SleekDB\Store;

class Auth implements PluginsInterface
{
    protected $terminal;

    protected $authStore;

    public function init(Terminal $terminal)
    {
        $this->terminal = $terminal;

        $this->authStore = new Store("auth", $this->terminal->databaseDirectory, $this->terminal->storeConfiguration);

        $accounts = $this->configStore->findAll();

        if ($accounts && count($accounts) === 0) {
            $this->authStore->updateOrInsert(
                [
                    '_id'       => 1,
                    'username'  => 'admin',
                    'password'  => $this->hashPassword('admin123')
                ]
            );
        }
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
                if ($this->passwordNeedsRehash($account[0]['password'])) {
                    $account[0]['password'] = $this->hashPassword($password);

                    $this->authStore->update($account);
                }

                return true;
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
            'settings' =>
            [
                'cost'      => 4,
                'hash'      => 'PASSWORD_BCRYPT'//Check needs to be there when changing constant via terminal, maybe present a list of available encryption and make user type the corresponding number.
            ]
        ];
    }
}