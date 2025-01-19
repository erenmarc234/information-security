<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use App\Models\User;
use App\Models\ParkingSlot;
use App\Models\Payment;
use App\Models\Activity;
use App\Models\Certificate;
use Validator;

class SystemController extends Controller
{
    /**
     * Encrypt data using a session key.
     */
    private function encryptData($data, $key)
    {
        return openssl_encrypt(
            json_encode($data),
            'AES-256-CBC',
            $key,
            0,
            substr($key, 0, 16)
        );
    }

    /**
     * Decrypt data using a session key.
     */
    private function decryptData($encryptedData, $key)
    {
        return json_decode(
            openssl_decrypt(
                $encryptedData,
                'AES-256-CBC',
                $key,
                0,
                substr($key, 0, 16)
            ),
            true
        );
    }

    /**
     * Generate a digital signature for data.
     */
    private function generateSignature($data, $key)
    {
        return hash_hmac('sha256', json_encode($data), $key);
    }

    /**
     * Verify a digital signature.
     */
    private function verifySignature($data, $signature, $key)
    {
        return hash_hmac('sha256', json_encode($data), $key) === $signature;
    }

    /**
     * Generate hybrid encryption keys.
     */
    private function generateKeys()
    {
        // إعدادات OpenSSL
        $config = [
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
    
        // محاولة إنشاء المفتاح الخاص
        $privateKey = openssl_pkey_new($config);
    
        if (!$privateKey) {
            throw new \Exception('Failed to generate private key: ' . openssl_error_string());
        }
    
        $privateKeyString = '';
        openssl_pkey_export($privateKey, $privateKeyString);
    
        $keyDetails = openssl_pkey_get_details($privateKey);
    
        return [
            'private_key' => $privateKeyString,
            'public_key' => $keyDetails['key'],
        ];
    }
    
    

    /**
     * Encrypt session key with public key.
     */
    private function encryptSessionKey($sessionKey, $publicKey)
    {
        openssl_public_encrypt($sessionKey, $encryptedKey, $publicKey);
        return base64_encode($encryptedKey);
    }

    /**
     * Decrypt session key with private key.
     */
    private function decryptSessionKey($encryptedKey, $privateKey)
    {
        openssl_private_decrypt(base64_decode($encryptedKey), $decryptedKey, $privateKey);
        return $decryptedKey;
    }

    /**
     * Issue a digital certificate.
     */
    /*public function issueCertificate(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'user_id' => 'required|exists:users,id',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $user = User::find($request->user_id);
        $keys = $this->generateKeys();

        $certificate = Certificate::create([
            'user_id' => $user->id,
            'public_key' => $keys['public_key'],
            'private_key' => $keys['private_key'],
            'issued_at' => now(),
        ]);

        return response()->json(['message' => 'Certificate issued successfully.', 'certificate' => $certificate], 201);
    }*/
    public function issueCertificate(Request $request)
    {
         $validator = Validator::make($request->all(), [
            'user_id' => 'required|exists:users,id',
        ]);
    
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
    
         $user = User::find($request->user_id);
    
         $certificate = Certificate::create([
            'user_id' => $user->id,
            'issued_at' => now(),
            'certificate_data' => 'Default certificate data', // أضف هذا السطر

        ]);
    
        return response()->json(['message' => 'Certificate issued successfully.', 'certificate' => $certificate], 201);
    }
    
    /**
     * Validate a digital certificate.
     */
    private function validateCertificate($certificateId)
    {
        $certificate = Certificate::find($certificateId);
        if (!$certificate) {
            return false;
        }

        // Example: Check if the certificate is expired (valid for 1 year)
        $issuedAt = strtotime($certificate->issued_at);
        $validUntil = strtotime('+1 year', $issuedAt);
        return time() <= $validUntil;
    }

    /**
     * Protect against XSS by sanitizing input.
     */
    private function sanitizeInput($input)
    {
        return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    }

    /**
     * Protect against SQL Injection by using parameterized queries.
     */
    private function secureQuery($query, $bindings = [])
    {
        return \DB::select($query, $bindings);
    }

    /**
     * Register a new user and sanitize inputs.
     */
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'full_name' => 'required|string|max:255',
            'user_type' => 'required|in:employee,visitor',
            'phone_number' => 'required|string|unique:users,phone_number',
            'car_plate' => 'nullable|string',
            'password' => 'required|string|min:8',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $user = User::create([
            'full_name' => $this->sanitizeInput($request->full_name),
            'user_type' => $this->sanitizeInput($request->user_type),
            'phone_number' => $this->sanitizeInput($request->phone_number),
            'car_plate' => $this->sanitizeInput($request->car_plate),
            'password' => Hash::make($request->password),
        ]);

        $token = $user->createToken('SystemAccessToken')->plainTextToken;

        return response()->json([
            'message' => 'User registered successfully.',
            'user' => $user,
            'token' => $token
        ], 201);
    }

    /**
     * Sanitize inputs in login function.
     */
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'phone_number' => 'required|string',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $phoneNumber = $this->sanitizeInput($request->phone_number);
        $user = User::where('phone_number', $phoneNumber)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json(['message' => 'Invalid credentials.'], 401);
        }

        $token = $user->createToken('SystemAccessToken')->plainTextToken;

        return response()->json([
            'message' => 'Login successful.',
            'user' => $user,
            'token' => $token
        ], 200);
    }

    /**
     * Get available parking slots.
     */
    public function getAvailableSlots()
    {
        $availableSlots = ParkingSlot::where('status', 'available')->get();
        return response()->json(['available_slots' => $availableSlots], 200);
    }

    /**
     * Book a parking slot with encryption and digital signature.
     */
    public function bookParking(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'slot_id' => 'required|exists:parking_slots,id',
            'start_time' => 'required|date|after_or_equal:now',
            'duration' => 'required|integer|min:1',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $slot = ParkingSlot::find($request->slot_id);

        if ($slot->status === 'occupied') {
            return response()->json(['message' => 'Parking slot is already occupied.'], 400);
        }

        // Validate user certificate
        $user = $request->user();
        if (!$this->validateCertificate($user->id)) {
            return response()->json(['message' => 'Invalid or expired certificate.'], 403);
        }

        $slot->update([
            'status' => 'occupied',
            'booked_by' => $user->id,
            'booking_time' => $request->start_time,
            'booking_duration' => $request->duration,
        ]);

        $sessionKey = Str::random(32);
        $signature = $this->generateSignature($slot->toArray(), $sessionKey);

        $activity = Activity::create([
            'activity_type' => 'booking',
            'user_id' => $user->id,
            'activity_data' => json_encode($slot->toArray()),
            'digital_signature' => $signature,
        ]);

        return response()->json(['message' => 'Parking slot booked successfully.', 'activity' => $activity], 200);
    }

    /**
     * Make a payment with encryption and digital signature.
     */
    public function makePayment(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'amount' => 'required|numeric|min:0.01',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $user = $request->user();

        // Validate user certificate
        if (!$this->validateCertificate($user->id)) {
            return response()->json(['message' => 'Invalid or expired certificate.'], 403);
        }

        $payment = Payment::create([
            'user_id' => $user->id,
            'amount' => $request->amount,
            'payment_status' => 'successful',
            'payment_time' => now(),
        ]);

        $sessionKey = Str::random(32);
        $signature = $this->generateSignature($payment->toArray(), $sessionKey);

        $activity = Activity::create([
            'activity_type' => 'payment',
            'user_id' => $user->id,
            'activity_data' => json_encode($payment->toArray()),
            'digital_signature' => $signature,
        ]);

        return response()->json(['message' => 'Payment processed successfully.', 'activity' => $activity], 201);
    }

    /**
     * Verify an activity's digital signature.
     */
    public function verifyActivitySignature(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'activity_id' => 'required|exists:activities,id',
            'session_key' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $activity = Activity::find($request->activity_id);
        $isValid = $this->verifySignature(json_decode($activity->activity_data, true), $activity->digital_signature, $request->session_key);

        return response()->json(['message' => $isValid ? 'Signature is valid.' : 'Invalid signature.'], $isValid ? 200 : 400);
    }

    /**
     * Get user activities.
     */
    public function getActivities(Request $request)
    {
        $activities = Activity::where('user_id', $request->user()->id)->get();
        return response()->json(['activities' => $activities], 200);
    }
}
