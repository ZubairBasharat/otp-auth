<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use App\Models\UserOtp;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Auth;
use Twilio\Rest\Client;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;
class UserController extends Controller
{
    public function register(Request $request) {
        $record = $request->all();
        $validation = Validator::make($record,[
            'email' => 'required|email|unique:users',
            'phone_number' => 'required|numeric|unique:users',
            'password' => 'required|min:8'
        ]);
        if($validation->fails()) {
            return response()->json(['errors'=> $validation->errors()], 422);
        }
        $user = User::create($record);
        $phone_number = $user->phone_number;
        $userOtp = $this->generateOtp($phone_number);
        $userOtp = UserOtp::where('user_id',$user->id)->latest()->first();
        $otp = $userOtp->otp;
        $account_sid = env('TWILIO_SID');
        $account_token = env('TWILIO_AUTH_TOKEN');
        $senderNumber = env('TWILIO_NUMBER');
        $client = new Client($account_sid,$account_token);
        $client->messages->create($phone_number,[
            'from' => $senderNumber,
            'body' => "Your verification OTP is:"." ".$otp
        ]);
        $token = $user->createToken('auth_token')->accessToken;
        return response()->json(['user'=> $user,'token'=> $token], 200);
    }

    public function login(Request $request) {
        $record = $request->all();
        $validation = Validator::make($record,[
            'email' => 'required|email',
            'password' => 'required|min:8',
            'otp' => 'exists:user_otps'
        ]);
        if($validation->fails()) {
            return response()->json(['errors'=> $validation->errors()], 422);
        }
        $user = User::where('email',$record['email'])->first();
        $userOtp = UserOtp::where('user_id',$user->id)->latest()->first();
        $now = now();
        if($userOtp == null) {
            $phone_number = $user->phone_number;
            $userOtp = $this->generateOtp($phone_number);
            $userOtp = UserOtp::where('user_id',$user->id)->latest()->first();
            $otp = $userOtp->otp;
            $account_sid = env('TWILIO_SID');
            $account_token = env('TWILIO_AUTH_TOKEN');
            $senderNumber = env('TWILIO_NUMBER');
            $client = new Client($account_sid,$account_token);
            $client->messages->create($phone_number,[
                'from' => $senderNumber,
                'body' => "Your verification OTP is:"." ".$otp
            ]);
            return response()->json(['message'=> 'OTP send to your phone number.Please Enter verification code here'],200);
        }
        else {
            if($userOtp && $now->isAfter($userOtp->expire_at)) {
                $userOtp->delete();
                $phone_number = $user->phone_number;
                $userOtp = $this->generateOtp($phone_number);
                $userOtp = UserOtp::where('user_id',$user->id)->latest()->first();
                $resendOtp = $userOtp->otp;
                $account_sid = env('TWILIO_SID');
                $account_token = env('TWILIO_AUTH_TOKEN');
                $senderNumber = env('TWILIO_NUMBER');
                $client = new Client($account_sid,$account_token);
                $client->messages->create($phone_number,[
                    'from' => $senderNumber,
                    'body' => "Your verification OTP is:"." ".$resendOtp
                ]);
                return response()->json(['message'=> 'Your otp has been Expired.New Otp sent to Your Phone number'], 400);
            }
            else {
                $newOtp = $userOtp->where('otp',$record['otp'])->first();
                if($newOtp)  {
                    if(Auth::attempt(['email'=> $record['email'],'password'=> $record['password']])) {
                        $user = Auth::user();
                        $token = $user->createToken('auth_token')->accessToken; 
                        $userOtp->delete();
                        return response()->json(['data'=> $user, 'token'=> $token], 200);
                    }
                    else {
                        return response()->json(['message'=> 'Invalid Credentials'], 400);
                    }
                }
            }
        }
    }

    public function single_user_record(Request $request) {
        $record = User::where('id',$request->id)->first();
        return response()->json(['user'=>$record]);
    }

    public function logout() {
        $user = Auth::user()->token();
        $user->revoke();
        return response()->json(['message'=> 'You have been logged out'], 200);
    }

    public function reset_password_with_email(Request $request) {
        $record = $request->all();
        $validation = Validator::make( $record,[
            'email' => 'required|email|exists:users'
        ]);
        if($validation->fails()) {
            return response()->json(['errors'=> $validation->errors()], 422);
        }
        $user = User::where('email', $request->email)->first();
        if($user) {
           $email = $user->email;
           $new_password = Str::random(8);
           $user->update([ 
              'password' => $new_password,
            ]);
           $userDetail = $user->toArray();
           $messageData = ['name' => $userDetail['name'],'email' => $email,'password' => $new_password];
           Mail::send('get-password',$messageData,function($message) use ($email) {
               $message->to($email);
               $message->subject('New Password');
            });
            return response()->json(['message'=> 'new Password sent to your Email'], 200);
        }
        else {
            return response()->json(['message'=> 'Invalid Email'], 400);
        }
    }

    public function generateOtp($phone_number) {
        $user = User::where('phone_number',$phone_number)->first();
        $userOtp = UserOtp::where('user_id',$user->id)->latest()->first();
        $now = now();
        if($userOtp && $now->isBefore($userOtp->expire_at)) {
            return $userOtp;
        }
        UserOtp::create([
           'user_id' => $user->id,
           'otp' => rand(1234,9999),
           'expire_at' => $now->addMinutes(5)
        ]);
        return $userOtp;    
    }
}
