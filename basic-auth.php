<?php
/**
 * Plugin Name: JSON Basic Authentication Hacked By JaeHo Song
 * Description: Basic Authentication handler for the JSON API which was originally develpoed by Wordpress Team and Hacked by JaeHo Song to add security for production use.
 * Author: JaeHo Song
 * Author URI: https://github.com/thruthesky/Basic-Auth
 * Version: 0.1
 * Plugin URI: https://github.com/thruthesky/Basic-Auth
 */

include_once 'domain.php';

define('ERROR_LOGIN_FIRST', 'login_first');

function error( $code, $message ) {

    return new WP_Error( $code, $message, array( 'status' => 400 ) );
}
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
    $allcaps['list_users'] = true;

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
    $user->add_role('author');
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
 * Register Rest API function here
 */
add_action( 'rest_api_init', function () {
    register_rest_route( 'custom/v1', '/profile', array(
        'methods' => 'GET',
        'callback' => 'custom_user_login',
        )
    );

    /**
     *  id - query value
     */
    register_rest_route( 'custom/api', '/users/(?P<id>\d+)', array(
        'methods' => 'GET',
        'callback' => 'custom_user_get',
        )
    );
}) ;


/**
 * Returns login user's data.
 */

function custom_user_login() {

    if ( is_user_logged_in() ) {
        $user = wp_get_current_user();
        $re = [
            'email' => $user->user_email,
            'id' => $user->ID,
            'name' => $user->display_name,
            'nickname' => $user->nickname,
            'register_date' => $user->user_registered,
            'username' => $user->user_login,
            'roles' => $user->roles,
            'security_code' => get_security_code($user->ID)
        ];
        return $re;
    } else {
        return null;
    }
};


/**
 * this might come in handy for searching a user along with their posts,
 * by default wordpress doesn't support this, even via embeding post to the user ( because we really cannot ).
 * this is one way of fetching user and post in a single api request,
 * 
 * the other way is to make a post API request then embed the user, but in terms of data response,
 * the user data will be incomplete.
 * 
 * I made this to for hussle free api requesting of user with their post and
 * to make a flexible single request for the app.
 * 
 * This is for user profile purpose.
 */
function custom_user_get( $data ) {

    // the query value, ID of the user being searched for
    $requestID = $data['id'];

    $requestData = get_userdata( $requestID );

    /**
     * This whole request will return null if the $data['id'] value being searched for is non existent on the database
     */
    if(!$requestData) {
        return null;
    }

    /**
     * add values from the user to the response, this is only for viewing purposes.
     * can be viewed by anyone
     */
    $userResponse = [
        'email' => $requestData->user_email,
        'id' => $requestData->ID,
        'name' => $requestData->display_name,
        'nickname' => $requestData->nickname,  
        'meta' => '',
        'register_date' => $requestData->user_registered,
        'username' => $requestData->user_login,
        'description' => $requestData->description,
        'roles' => $requestData->roles,
        
        /**
         * this field stays (for now,) for the purpose of displaying dummy image for a user,
         * after some time this will be removed when custom file upload method is applied
         */
        'avatars_urls' => rest_get_avatar_urls( $requestData->user_email ),
    ];

    $postQuery = [
        'numberposts'   =>  -1,
        'author'        =>  $requestID,
        'orderby'       =>  'post_date',
        'order'         =>  'DESC',
        'post_status'   =>  ['publish']
    ];

    $publishedPosts = get_posts( $postQuery );

    $draftedPosts = null;

    /**
     * this is only available if the user being searched for is the current logged in user itself,
     * for the purpose of reference if the user is going to edit and update his profile information.
     */
    if ( wp_get_current_user( )->ID == $requestID) {
        $userResponse['first_name'] = wp_get_current_user( )->first_name;
        $userResponse['last_name'] = wp_get_current_user( )->last_name;
        $userResponse['security_code'] = get_security_code( wp_get_current_user( )->ID );

        /**
         * drafts, incomplete or unpublished post are added to the response if the user is searching for
         * his/her own, or getting his/her own profile
         */
        $postQuery['post_status'] = ['draft'];
        $draftedPosts = get_posts( $postQuery );
    };

    /**
     * format the response for easier accessability
     * 
     * drafted post will only be accessible by tne currently logged in user
     */
    $dataResponse = [
        'info' => $userResponse,
        'posts' => [
            'published' => $publishedPosts,
            'drafts' => $draftedPosts ]
    ];

    return $dataResponse;
}
