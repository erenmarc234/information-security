<?php

namespace App\Models;
use Illuminate\Database\Eloquent\Factories\HasFactory;

use Illuminate\Database\Eloquent\Model;

class Payment extends Model
{
    use HasFactory;

    protected $fillable = ['user_id', 'amount', 'payment_status', 'payment_time'];

    public function user()
    {
        return $this->belongsTo(User::class);
    }
}