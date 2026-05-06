<?php

namespace App\Http\Controllers;

use App\Models\Usuario;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        try {
            $request->validate([
                'username' => 'required',
                'password' => 'required'
            ]);

            $usuario = Usuario::with(['persona', 'roles.rol', 'persona.carreras.carrera'])
                ->where('username', $request->username)
                ->first();

            if (!$usuario || !Hash::check($request->password, $usuario->password)) {
                return response()->json([
                    'error' => 'Credenciales incorrectas'
                ], 401);
            }

            $token = $usuario->createToken('auth_token')->plainTextToken;

            return response()->json([
                'access_token' => $token,
                'token_type'   => 'Bearer',
                'user'         => [
                    'id'       => $usuario->idusuario,
                    'username' => $usuario->username,
                    'persona'  => [
                        'nombres'   => $usuario->persona->nombres,
                        'apellidos' => $usuario->persona->apellidos,
                        'email'     => $usuario->persona->email
                    ],
                    'roles' => $usuario->roles->map(function ($userRole) {
                        return [
                            'id'     => $userRole->rol->idrol,
                            'nombre' => $userRole->rol->nombre
                        ];
                    }),
                    'carreras' => $usuario->persona->carreras->map(function ($personaCarrera) {
                        return [
                            'id'     => $personaCarrera->carrera->idcarrera,
                            'nombre' => $personaCarrera->carrera->nombre
                        ];
                    })
                ]
            ]);
        } catch (\Exception $e) {
            return response()->json([
                'error'   => 'Error en el inicio de sesión',
                'details' => $e->getMessage()
            ], 500);
        }
    }

    public function logout(Request $request)
    {
        try {
            $this->validateLogoutRequest($request);
            $request->user()->tokens()->delete();
            return response()->json(['message' => 'Sesión cerrada'], 200);
        } catch (\Exception $e) {
            return response()->json(['details' => $e->getMessage()], 500);
        }
    }

    private function validateLogoutRequest(Request $request): void
    {
        if (!$request->user())
            throw new \Exception('No hay sesión activa', 401);

        if ($request->user()->tokens()->count() === 0)
            throw new \Exception('No se encontraron tokens activos', 400);
    }
}
