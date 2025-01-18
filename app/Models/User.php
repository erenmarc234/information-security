<?php

namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;  // إضافة هذه السطر
 
class User extends Authenticatable
{
    use HasFactory;
    use HasApiTokens;  // تأكد من أنك تستخدم HasApiTokens هنا

    protected $fillable = ['full_name', 'user_type', 'phone_number', 'car_plate', 'password'];

    public function parkingSlots()
    {
        return $this->hasMany(ParkingSlot::class, 'booked_by');
    }

    public function payments()
    {
        return $this->hasMany(Payment::class);
    }

    public function activities()
    {
        return $this->hasMany(Activity::class);
    }

    public function certificates()
    {
        return $this->hasOne(Certificate::class);
    }
}
