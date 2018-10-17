<?php
/**
 * Plugin Name: JSON Basic Authentication Hacked By JaeHo Song
 * Description: Basic Authentication handler for the JSON API which was originally develpoed by Wordpress Team and Hacked by JaeHo Song to add security for production use.
 * Author: JaeHo Song
 * Author URI: https://github.com/thruthesky/Basic-Auth
 * Version: 0.1
 * Plugin URI: https://github.com/thruthesky/Basic-Auth
 */

/**
 * This is being called whenever Rest Api is access to authenticate the user.
 *
 * @param $user
 * @return bool|int|mixed|null|void|WP_Error|WP_User
 */
function json_basic_auth_handler( $user ) {
	global $wp_json_basic_auth_error;

	$wp_json_basic_auth_error = null;

	// Don't authenticate twice
	if ( ! empty( $user ) ) {
		return $user;
	}

	// Check that we're trying to authenticate
	if ( !isset( $_SERVER['PHP_AUTH_USER'] ) ) {
		return $user;
	}

	$username = $_SERVER['PHP_AUTH_USER'];
	$password = $_SERVER['PHP_AUTH_PW'];


    /**
     * Hacked by JaeHo Song.
     * Check if the user is using security code instead of plain password.
     */
	if ( is_numeric($username) ) {
	    $user = get_userdata($username);
        $security_code = get_security_code( $user->ID );
        if ( $password == $security_code ) {
            wp_set_current_user($user->ID);
            $wp_json_basic_auth_error = true;
            return $user->ID;
        }
    }

	/**
	 * In multi-site, wp_authenticate_spam_check filter is run on authentication. This filter calls
	 * get_currentuserinfo which in turn calls the determine_current_user filter. This leads to infinite
	 * recursion and a stack overflow unless the current function is removed from the determine_current_user
	 * filter during authentication.
	 */
	remove_filter( 'determine_current_user', 'json_basic_auth_handler', 20 );

	$user = wp_authenticate( $username, $password );

	add_filter( 'determine_current_user', 'json_basic_auth_handler', 20 );

	if ( is_wp_error( $user ) ) {
		$wp_json_basic_auth_error = $user;
		return null;
	}

	$wp_json_basic_auth_error = true;

	return $user->ID;
}
add_filter( 'determine_current_user', 'json_basic_auth_handler', 20 );

/**
 * @param $error
 * @return mixed
 */
function json_basic_auth_error( $error ) {
	// Passthrough other errors
	if ( ! empty( $error ) ) {
		return $error;
	}

	global $wp_json_basic_auth_error;

	return $wp_json_basic_auth_error;
}
add_filter( 'rest_authentication_errors', 'json_basic_auth_error' );


/**
 * This allow anyone can register into wordpress through Rest Api.
 *
 * author_cap_filter()
 *
 * Filter on the current_user_can() function.
 * This function is used to explicitly allow authors to edit contributors and other
 * authors posts if they are published or pending.
 *
 * @param array $allcaps All the capabilities of the user
 * @param array $cap [0] Required capability
 * @param array $args [0] Requested capability
 *                       [1] User ID
 *                       [2] Associated object ID
 * @return array
 */
function give_permissions( $allcaps, $cap, $args ) {
                                //    $allcaps['rest_cannot_create'] = true; // This is not working. 이것을 해도 사용자가 Rest Api 로 글 작성 할 수 없음. 그래서 아래와 같이 회원 가입하면 권한을 줌.
                                //    $allcaps[$cap[0]] = true; // This is wrong. 이렇게 하면, 모든 요청되는 권한을 주므로 안된다.

    /**
     * Allow anyone can register
     */
    $allcaps['create_users'] = true;

    /**
     * Allow user update only his user data. Not others.
     * $args[1] is login user's ID.
     * $args[2] is the user ID that will be updated.
     */
    if ( $args[1] == $args[2] ) {
        $allcaps['edit_users'] = true;
    }


    return $allcaps;
}
add_filter( 'user_has_cap', 'give_permissions', 10, 3 );

/**
 * This function is being invoked right after user registered.
 * It gives 'editor' role to newly registered users so they can create posts.
 *
 * @param $user_id
 */
function do_user_register( $user_id ) {
    $user = new WP_User($user_id);
    $user->remove_role('subscriber');
    $user->add_role('editor');
}
add_action( 'user_register', 'do_user_register', 10, 1 );


/**
 * It returns user's security code every 'user' Rest Api call.
 * @note When user is not logged in(Especially when user has registered), it compares if the user is the last user who registered to wordpress,
 *          If the user is the last user ( Meaning, just registered, returns security code also.
 * It only returns if my user information is requested. Meaning security code for others will not be returned.
 */
register_rest_field( 'user', 'security_code',
    array(
        'get_callback'    => function ( $user ) {
            if ( $user['id'] == wp_get_current_user()->ID || $user['id'] == get_last_user_ID() ) {
                return get_security_code( $user['id'] );
            }
        },
        'update_callback' => null,
        'schema'          => null,
    )
);
//register_rest_field( 'user', 'whatever',
//    array(
//        'get_callback'    => function ( $user ) {
//            if ( $user['id'] == wp_get_current_user()->ID || $user['id'] == get_last_user_ID() ) {
//                $u = get_userdata($user['id']);
//                return $u->name;
//            }
//        },
//        'update_callback' => null,
//        'schema'          => null,
//    )
//);



/**
 * Returns the user security code.
 *
 * @param int $ID User ID
 * @return string
 */
function get_security_code( $ID ) {
    $user = get_userdata($ID);
    $security_source = "{$user->ID},{$user->user_email},{$user->user_registered},{$user->user_pass}";
    return md5($security_source);
}


function get_last_user_ID() {
    $args = array(
//        'role'         => 'author', // authors only
        'orderby'      => 'registered', // registered date
        'order'        => 'DESC', // last registered goes first
        'number'       => 1 // limit to the last one, not required
    );

    $users = get_users( $args );

    $last_user_registered = $users[0]; // the first user from the list

    return $last_user_registered->ID;
}


/**
 * Returns login user's data.
 */
add_action( 'rest_api_init', function () {
    register_rest_route( 'custom/api', '/profile', array(
        'methods' => 'GET',
        'callback' => function() {

            if ( is_user_logged_in() ) {
                $user = wp_get_current_user();
                $re = [
                    'email' => $user->user_email,
                    'id' => $user->ID,
                    'first_name' => $user->first_name,
                    'last_name' => $user->last_name,
                    'name' => $user->display_name,
                    'nickname' => $user->nickname,
                    'meta' => '',
                    'register_date' => $user->user_registered,
                    'username' => $user->user_login,
                    'security_code' => get_security_code($user->ID)
                ];

                return $re;
            } else {
                return null;
            }
        },
    ) );
} );
