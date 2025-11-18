<?php

require __DIR__ . '/vendor/autoload.php';
require 'firebase.php';

try {
    $database = getDatabase();
    
    // Add sample data
    $database->getReference('test_data')->set([
        'users' => [
            'user1' => [
                'email' => 'test1@example.com',
                'timestamp' => date('Y-m-d H:i:s')
            ],
            'user2' => [
                'email' => 'test2@example.com',
                'timestamp' => date('Y-m-d H:i:s')
            ]
        ]
    ]);
    
    echo "Sample data added successfully!";
} catch (Exception $e) {
    echo "Error: " . $e->getMessage();
}