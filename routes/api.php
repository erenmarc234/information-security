<?php

   use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\SystemController;
 
// مسارات عامة
Route::post('/register', [SystemController::class, 'register']);
Route::post('/login', [SystemController::class, 'login']);

// مسارات الزوار
Route::middleware('auth:sanctum')->group(function () {
    Route::get('/view-parking-slots', [SystemController::class, 'viewParkingSlots']);
    Route::post('/book-parking-slot', [SystemController::class, 'bookParkingSlot']);
    Route::get('/booking-history', [SystemController::class, 'viewBookingHistory']);
    Route::post('/make-payment', [SystemController::class, 'makePayment']);

    Route::get('/server-public-key', [SystemController::class, 'getPublicKey']);

    Route::post('/manage-parking-slots', [SystemController::class, 'manageParkingSlots']);
    Route::put('/update-parking-slot/{id}', [SystemController::class, 'updateParkingSlot']);
    Route::delete('/delete-parking-slot/{id}', [SystemController::class, 'deleteParkingSlot']);
    Route::get('/view-all-bookings', [SystemController::class, 'viewAllBookings']);
    Route::get('/view-slot-statuses', [SystemController::class, 'viewSlotStatuses']);
});

// مسارات الموظفين
Route::middleware(['auth:sanctum', 'employee'])->group(function () {
   
});
