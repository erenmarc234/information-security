<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class ParkingSlot extends Model
{
    use HasFactory;

    protected $fillable = ['slot_number', 'status', 'booked_by', 'booking_time'];

    public function user()
    {
        return $this->belongsTo(User::class, 'booked_by');
    }
}
