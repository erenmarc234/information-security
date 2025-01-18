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
     * Register a new user and generate an access token.
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

        // Generate access token
        $token = $user->createToken('SystemAccessToken')->plainTextToken;

        return response()->json([
            'message' => 'User registered successfully.',
            'user' => $user,
            'token' => $token
        ], 201);
    }

    /**
     * Login a user and generate an access token.
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

        // Generate access token
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
     * Book a parking slot.
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

        $slot->update([
            'status' => 'occupied',
            'booked_by' => $request->user()->id,
            'booking_time' => $request->start_time,
            'booking_duration' => $request->duration,
        ]);

        $activity = Activity::create([
            'activity_type' => 'booking',
            'user_id' => $request->user()->id,
            'activity_data' => json_encode($slot->toArray()),
            'digital_signature' => hash_hmac('sha256', json_encode($slot->toArray()), Str::random(32)),
        ]);

        return response()->json(['message' => 'Parking slot booked successfully.', 'activity' => $activity], 200);
    }

    /**
     * Make a payment.
     */
    public function makePayment(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'amount' => 'required|numeric|min:0.01',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $payment = Payment::create([
            'user_id' => $request->user()->id,
            'amount' => $request->amount,
            'payment_status' => 'successful',
            'payment_time' => now(),
        ]);

        $activity = Activity::create([
            'activity_type' => 'payment',
            'user_id' => $request->user()->id,
            'activity_data' => json_encode($payment->toArray()),
            'digital_signature' => hash_hmac('sha256', json_encode($payment->toArray()), Str::random(32)),
        ]);

        return response()->json(['message' => 'Payment processed successfully.', 'activity' => $activity], 201);
    }

    /**
     * Add a parking slot (employee only).
     */
    public function addSlot(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'slot_number' => 'required|string|unique:parking_slots,slot_number',
            'status' => 'required|in:available,occupied',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $slot = ParkingSlot::create($request->all());

        return response()->json(['message' => 'Slot added successfully.', 'slot' => $slot], 201);
    }

    /**
     * Update a parking slot (employee only).
     */
    public function updateSlot(Request $request, $id)
    {
        $slot = ParkingSlot::findOrFail($id);

        $validator = Validator::make($request->all(), [
            'slot_number' => 'string|unique:parking_slots,slot_number,' . $slot->id,
            'status' => 'in:available,occupied',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $slot->update($request->all());

        return response()->json(['message' => 'Slot updated successfully.', 'slot' => $slot], 200);
    }

    /**
     * Delete a parking slot (employee only).
     */
    public function deleteSlot($id)
    {
        $slot = ParkingSlot::findOrFail($id);
        $slot->delete();

        return response()->json(['message' => 'Slot deleted successfully.'], 200);
    }

    /**
     * Get user activities.
     */
    public function getActivities(Request $request)
    {
        $activities = Activity::where('user_id', $request->user()->id)->get();
        return response()->json(['activities' => $activities], 200);
    }

    /**
     * Get all bookings (employee only).
     */
    public function getAllBookings()
    {
        $bookings = Activity::where('activity_type', 'booking')->get();
        return response()->json(['bookings' => $bookings], 200);
    }
}
