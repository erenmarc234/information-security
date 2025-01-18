<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
      // ParkingSlots Table
      Schema::create('parking_slots', function (Blueprint $table) {
        $table->id();
        $table->string('slot_number')->unique();
        $table->enum('status', ['occupied', 'available'])->default('available');
        $table->foreignId('booked_by')->nullable()->constrained('users')->onDelete('cascade');
        $table->timestamp('booking_time')->nullable();
        $table->timestamps();
    });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('parking_slots');
    }
};
