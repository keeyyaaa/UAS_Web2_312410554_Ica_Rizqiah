<?php

namespace App\Controllers;

use CodeIgniter\RESTful\ResourceController;
use CodeIgniter\API\ResponseTrait;
use Firebase\JWT\JWT;

class Auth extends ResourceController
{
    use ResponseTrait;

    public function login()
    {
        $db = \Config\Database::connect();
        
        $rules = [
            'username' => 'required',
            'password' => 'required'
        ];

        if (!$this->validate($rules)) {
            return $this->fail($this->validator->getErrors());
        }

        $username = $this->request->getVar('username');
        $password = $this->request->getVar('password');

        $user = $db->table('users')->where('username', $username)->get()->getRowArray();

        if (!$user) {
            return $this->failNotFound('Username tidak ditemukan');
        }

        if (!password_verify($password, $user['password'])) {
            return $this->fail('Password salah');
        }

        $key = getenv('JWT_SECRET');
        $iat = time(); // Waktu token dibuat
        $exp = $iat + 3600; // Token kedaluwarsa dalam 1 jam

        $payload = array(
            "iat" => $iat,
            "exp" => $exp,
            "uid" => $user['id'],
            "username" => $user['username'],
            "role" => $user['role']
        );

        $token = JWT::encode($payload, $key, 'HS256');

        return $this->respond([
            'status' => 200,
            'message' => 'Login Berhasil',
            'token' => $token,
            'user' => [
                'username' => $user['username'],
                'role' => $user['role']
            ]
        ], 200);
    }
}