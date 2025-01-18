<?php

use Illuminate\Http\Request;
 use Illuminate\Support\Facades\Route;
use App\Http\Controllers\SystemController;

// User Authentication and General Operations
Route::prefix('system')->group(function () {
    // User Routes
    Route::post('/register', [SystemController::class, 'register']);
    Route::post('/login', [SystemController::class, 'login']);

    // Protected Routes (Requires Authentication)
    Route::middleware('auth:sanctum')->group(function () {
        // Visitor-Specific Operations
        Route::get('/available-slots', [SystemController::class, 'getAvailableSlots']);
        Route::post('/book-parking', [SystemController::class, 'bookParking']);
        Route::post('/make-payment', [SystemController::class, 'makePayment']);
        Route::get('/my-activities', [SystemController::class, 'getActivities']);

        // Employee-Specific Operations
        Route::middleware('can:manage-slots')->group(function () {
            Route::post('/add-slot', [SystemController::class, 'addSlot']);
            Route::put('/update-slot/{id}', [SystemController::class, 'updateSlot']);
            Route::delete('/delete-slot/{id}', [SystemController::class, 'deleteSlot']);
            Route::get('/all-bookings', [SystemController::class, 'getAllBookings']);
        });
    });
});