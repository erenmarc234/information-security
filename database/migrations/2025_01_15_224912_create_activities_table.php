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
       // Activities Table
       Schema::create('activities', function (Blueprint $table) {
        $table->id();
        $table->enum('activity_type', ['booking', 'payment']);
        $table->foreignId('user_id')->constrained('users')->onDelete('cascade');
        $table->text('activity_data');
        $table->text('digital_signature');
        $table->timestamps();
    });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('activities');
    }
};
