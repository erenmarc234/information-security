<?php

namespace Database\Seeders;

use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use App\Models\ParkingSlot;

class ParkingSlotSeeder extends Seeder
{
    public function run()
    {
        ParkingSlot::create(['slot_number' => 101, 'status' => 'available']);
        ParkingSlot::create(['slot_number' => 102, 'status' => 'occupied', 'booked_by' => 1, 'booking_time' => now()]);
        ParkingSlot::create(['slot_number' => 103, 'status' => 'available']);
        ParkingSlot::create(['slot_number' => 104, 'status' => 'available']);
        ParkingSlot::create(['slot_number' => 105, 'status' => 'occupied', 'booked_by' => 2, 'booking_time' => now()]);
        ParkingSlot::create(['slot_number' => 106, 'status' => 'available']);
        ParkingSlot::create(['slot_number' => 107, 'status' => 'available']);
        ParkingSlot::create(['slot_number' => 108, 'status' => 'occupied', 'booked_by' => 3, 'booking_time' => now()]);
        ParkingSlot::create(['slot_number' => 109, 'status' => 'available']);
        ParkingSlot::create(['slot_number' => 110, 'status' => 'occupied', 'booked_by' => 4, 'booking_time' => now()]);
    }
    
}
