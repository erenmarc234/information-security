<?php

namespace App\Models;
use Illuminate\Database\Eloquent\Factories\HasFactory;

use Illuminate\Database\Eloquent\Model;

class Activity extends Model
{
    use HasFactory;

    protected $fillable = ['activity_type', 'user_id', 'activity_data', 'digital_signature'];

    public function user()
    {
        return $this->belongsTo(User::class);
    }
}