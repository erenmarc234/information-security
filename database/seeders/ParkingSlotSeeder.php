<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use App\Models\ParkingSlot;

class ParkingSlotSeeder extends Seeder
{
    public function run()
    {
        ParkingSlot::create(['slot_number' => 1, 'status' => 'available']);
        ParkingSlot::create(['slot_number' => 2, 'status' => 'occupied', 'booked_by' => 1, 'booking_time' => now()]);
        ParkingSlot::create(['slot_number' => 3, 'status' => 'available']);
    }
}
