<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class UsersController extends Controller
{
    public function register(request $request){
     $rules= [
        'name'=>'required|max: 255',
        'email'=>'required|email|unique:users',
        'password' => 'required|min:6',
        'c_password' => 'required|same:password'
    ];
    $data=request()->all();
    $valid=Validator::make($data,$rules);
    if(count($valid->errors())){
        return response([
            'errors' => 'failed',
            $valid->errors(),
        ]);
    }
    $user= new User();
    $user->name=$data['name'];
    $user->email=$data['email'];
    $user->password=Hash::make($request->password);
    $user->save();

    $token=$user->createToken('token')->plainTextToken;
    return response()->json([
        'token'=>$token,
        'status'=>'success',
        'user'=>$user
    ]);
}
public function login(Request $request)
{
    $data = $request->all();
    $rules = [
        'email' => 'required|email',
        'password' => 'required',
    ];
    $validator = Validator::make($data, $rules);

    if ($validator->fails()) {
        return response([
            'status' => 'failed',
            'message' => 'Enter correct details',
            'errors' => $validator->errors()->all()
        ], 422);
    } else {
        $email = $request->input('email');
        $password = $request->input('password');
        $user = User::where('email', $email)->first();

        if ($user && Auth::attempt(['email' => $email, 'password' => $password])) {
            $token = $user->createToken('token')->plainTextToken;
            return response([
                'status' => 'success',
                'token' => $token,
                'user' => $user // Use $user instead of request()->user()
            ]);
        } else {
            return response([
                'status' => 'failed',
                'message' => 'Invalid credentials'
            ], 401); // Unauthorized status code
        }
    }
}

}
