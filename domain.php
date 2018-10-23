<?php
$domain_table = 'sonub_domain_application';

function mySites($user_ID) {
    global $wpdb, $domain_table;

    return $wpdb->get_results("SELECT * FROM $domain_table", ARRAY_A);
    return [];
}