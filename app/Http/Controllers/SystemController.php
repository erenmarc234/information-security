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

    private function encryptData($data, $key)
{
    $iv = random_bytes(16);  
    $encrypted = openssl_encrypt(
        json_encode($data),
        'AES-256-CBC',
        $key,
        0,
        $iv
    );

    return base64_encode($iv . $encrypted);  
}

private function decryptData($encryptedData, $key)
{
    $data = base64_decode($encryptedData);
    $iv = substr($data, 0, 16); // استخراج IV
    $ciphertext = substr($data, 16); // استخراج النص المشفر

    return json_decode(
        openssl_decrypt(
            $ciphertext,
            'AES-256-CBC',
            $key,
            0,
            $iv
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

  
    private function generateKeys()
    {
        $config = [
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
    
        $privateKey = openssl_pkey_new($config);
    
        if (!$privateKey) {
            throw new \Exception('Failed to generate private key: ' . openssl_error_string());
        }
    
        openssl_pkey_export($privateKey, $privateKeyString);
    
        $keyDetails = openssl_pkey_get_details($privateKey);
    
        if (!isset($keyDetails['key'])) {
            throw new \Exception('Failed to retrieve public key: ' . openssl_error_string());
        }
    
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
         // التحقق من أن المكتبة OpenSSL مفعلة
         if (!extension_loaded('openssl')) {
             throw new \Exception('OpenSSL extension is not enabled.');
         }
     
         // التحقق من أن المفتاح العام ليس فارغًا
         if (!$publicKey) {
             throw new \Exception('Public key is missing.');
         }
     
         // التحقق من التنسيق وإضافة الرؤوس إذا كانت مفقودة
         if (strpos($publicKey, '-----BEGIN PUBLIC KEY-----') === false) {
             $publicKey = "-----BEGIN PUBLIC KEY-----\n" . chunk_split($publicKey, 64, "\n") . "-----END PUBLIC KEY-----";
         }
     
         // التحقق من صحة المفتاح العام
         $resource = openssl_pkey_get_public($publicKey);
         if (!$resource) {
             throw new \Exception('Invalid public key format: ' . openssl_error_string());
         }
     
         // تشفير مفتاح الجلسة باستخدام المفتاح العام
         if (!openssl_public_encrypt($sessionKey, $encryptedKey, $resource)) {
             throw new \Exception('Failed to encrypt session key: ' . openssl_error_string());
         }
     
         return base64_encode($encryptedKey);
     }
     
     private function decryptSessionKey($encryptedKey, $privateKey)
     {
         $resource = openssl_pkey_get_private($privateKey);
     
         if (!$resource) {
             throw new \Exception('Invalid private key provided.');
         }
     
         if (!openssl_private_decrypt(base64_decode($encryptedKey), $decryptedKey, $resource)) {
             throw new \Exception('Failed to decrypt session key: ' . openssl_error_string());
         }
     
         return $decryptedKey;
     }
     


 
   
    public function issueCertificate(Request $request)
    {

        $validator = Validator::make($request->all(), [
            'user_id' => 'required|exists:users,id',
        ]);
    
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
    
        $user = User::find($request->user_id);
        $keys = $this->generateKeys();
    
        try {
            $certificate = Certificate::create([
                'user_id' => $user->id,
                'public_key' => $keys['public_key'],
                'private_key' => $keys['private_key'], // حذف المفتاح الخاص إذا كان حساسًا.
                'issued_at' => now(),
            ]);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Failed to issue certificate: ' . $e->getMessage()], 500);
        }
    
        return response()->json(['message' => 'Certificate issued successfully.', 'certificate' => $certificate], 201);
    }
    
    /**
     * Register a new user and assign roles.
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
            'full_name' => $request->full_name,
            'user_type' => $request->user_type,
            'phone_number' => $request->phone_number,
            'car_plate' => $request->car_plate,
            'password' => Hash::make($request->password),
        ]);

        $keys = $this->generateKeys();

        Certificate::create([
            'user_id' => $user->id,
            'public_key' => $keys['public_key'],
            'private_key' => $keys['private_key'],
            'issued_at' => now(),
            'certificate_data' => json_encode([
        'public_key' => $keys['public_key'],
        'private_key' => $keys['private_key']
    ])
        ]);

        $token = $user->createToken('SystemAccessToken')->plainTextToken;

        return response()->json([
            'message' => 'User registered successfully.',
            'user' => $user,
            'token' => $token,
        ], 201);
    }

    /**
     * Handle login and access control.
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

        $user = User::where('phone_number', $request->phone_number)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json(['message' => 'Invalid credentials.'], 401);
        }

        $certificate = Certificate::where('user_id', $user->id)->first();
        if (!$certificate) {
            return response()->json(['message' => 'Certificate not found.'], 403);
        }

        $token = $user->createToken('SystemAccessToken')->plainTextToken;

        return response()->json([
            'message' => 'Login successful.',
            'token' => $token,
        ], 200);
    }

    /**
     * Allow visitors to view parking slots.
     */
    public function viewParkingSlots()
    {
        $slots = ParkingSlot::where('status', 'available')->get();

        return response()->json(['available_slots' => $slots]);
    }

    /**
     * Allow visitors to book a parking slot.
     */
    public function bookParkingSlot(Request $request)
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

        $slot->update([
            'status' => 'occupied',
            'booked_by' => auth()->id(),
            'booking_time' => $request->start_time,
            'booking_duration' => $request->duration,
        ]);

        $sessionKey = Str::random(32);
        $signature = $this->generateSignature($slot->toArray(), $sessionKey);

        Activity::create([
            'activity_type' => 'booking',
            'user_id' => auth()->id(),
            'activity_data' => json_encode($slot->toArray()),
            'digital_signature' => $signature,
        ]);

        return response()->json(['message' => 'Parking slot booked successfully.']);
    }

    /**
     * Allow visitors to view their booking history.
     */
    public function viewBookingHistory()
    {
        $bookings = ParkingSlot::where('booked_by', auth()->id())->get();

        return response()->json(['booking_history' => $bookings]);
    }

    /**
     * Allow visitors to make payments with hybrid encryption.
     */
    public function makePayment(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'amount' => 'required|numeric|min:0.01',
        ]);
    
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
    
        $user = auth()->user();
        $sessionKey = Str::random(32);
    
        // استرجاع الشهادة
        $certificate = Certificate::where('user_id', $user->id)->first();
    
        if (!$certificate) {
            return response()->json(['error' => 'Certificate not found for the user.'], 404);
        }
    
        // استخراج المفتاح العام من certificate_data
        $certificateData = json_decode($certificate->certificate_data, true);
    
        if (!isset($certificateData['public_key'])) {
            return response()->json(['error' => 'Public key is missing in certificate data.'], 400);
        }
    
        $publicKey = $certificateData['public_key'];
    
        // تشفير مفتاح الجلسة
        $encryptedSessionKey = $this->encryptSessionKey($sessionKey, $publicKey);
    
        $payment = Payment::create([
            'user_id' => $user->id,
            'amount' => $request->amount,
            'payment_status' => 'successful',
            'payment_time' => now(),
        ]);
    
        $signature = $this->generateSignature($payment->toArray(), $sessionKey);
    
        Activity::create([
            'activity_type' => 'payment',
            'user_id' => $user->id,
            'activity_data' => json_encode($payment->toArray()),
            'digital_signature' => $signature,
        ]);
    
        return response()->json([
            'message' => 'Payment processed successfully.',
            'encrypted_session_key' => $encryptedSessionKey,
        ]);
    }
    
    /**
     * Allow employees to manage parking slots.
     */
    public function manageParkingSlots(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'slot_number' => 'required|string|unique:parking_slots,slot_number',
            'status' => 'required|in:available,occupied',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $slot = ParkingSlot::create([
            'slot_number' => $request->slot_number,
            'status' => $request->status,
        ]);

        return response()->json(['message' => 'Parking slot added successfully.', 'slot' => $slot]);
    }

    /**
     * Allow employees to update parking slots.
     */
    public function updateParkingSlot(Request $request, $id)
    {
        $validator = Validator::make($request->all(), [
            'status' => 'required|in:available,occupied',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $slot = ParkingSlot::find($id);

        if (!$slot) {
            return response()->json(['message' => 'Parking slot not found.'], 404);
        }

        $slot->update([
            'status' => $request->status,
        ]);

        return response()->json(['message' => 'Parking slot updated successfully.']);
    }

    /**
     * Allow employees to delete parking slots.
     */
    public function deleteParkingSlot($id)
    {
        $slot = ParkingSlot::find($id);

        if (!$slot) {
            return response()->json(['message' => 'Parking slot not found.'], 404);
        }

        $slot->delete();

        return response()->json(['message' => 'Parking slot deleted successfully.']);
    }

    /**
     * Allow employees to view all bookings.
     */
    public function viewAllBookings()
    {
        $bookings = ParkingSlot::where('status', 'occupied')->get();

        return response()->json(['all_bookings' => $bookings]);
    }

    /**
     * Allow employees to view parking slot statuses.
     */
    public function viewSlotStatuses()
    {
        $slots = ParkingSlot::all();

        return response()->json(['slots' => $slots]);
    }
}
