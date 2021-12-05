<?php
/*
 * Le Duy Vu
 * Midterm 2
 */

/*
 * MySQL code
 * CREATE DATABASE midterm2 ;
 * USE midterm2 ;
 *
 * CREATE TABLE user
 * (
 *      username VARCHAR(64) PRIMARY KEY,
 *      password VARCHAR(64) NOT NULL
 * ) ;
 *
 * CREATE TABLE content
 * (
 *      username VARCHAR(64) NOT NULL,
 *      content_name VARCHAR(64) NOT NULL,
 *      file_content TEXT
 * ) ;
 */

//error code
$FATAL_ERROR = 0 ;
$INSERT_ERROR = 1 ;
$RETRIEVE_ERROR = 2 ;

//connect to database
require_once 'login.php' ;
$conn = @new mysqli($hn, $un, $pw, $db_5) ;
if ($conn->connect_error) die(mysqlError($FATAL_ERROR)) ;

session_start() ;   // start the session

//logic to sign up
if (!empty($_POST["signUpUsername"]) || !empty($_POST["signUpPassword"]))
{
    if (!empty($_POST["signUpUsername"]) && !empty($_POST["signUpPassword"]))   //all boxes have input
    {
        //check if this username was already taken
        $statement = $conn->prepare('SELECT * FROM user WHERE username = ?') ;
        $statement->bind_param('s', $username) ;
        $username = sanitizeMySQL($conn, $_POST['signUpUsername']) ;   //sanitize input
        $statement->execute() ;
        $result = $statement->get_result() ;
        
        if ($result)    //if statement goes through
        {
            if (!$result->num_rows)     //username is new
            {
                //insert a new user into the database
                $statement = $conn->prepare('INSERT INTO user VALUES(?,?)') ;
                $statement->bind_param('ss', $username, $password) ;
                
                //sanitize username and hash password
                $username = sanitizeMySQL($conn, $_POST['signUpUsername']) ;
                $password = password_hash(sanitizeMySQL($conn, $_POST['signUpPassword']), PASSWORD_DEFAULT) ;
                $statement->execute() ;
                
                if ($statement->affected_rows)
                    $_SESSION['username'] = $_POST["signUpUsername"] ;  //user is automatically logged in
                    else $insertSignupError = true ;    //insert error
                    
                    $result->close() ;
            }
            else $nameTaken = true ;    //name was taken error
        }
        else $retrieveSignUpError = true ;    //retrieve error
        
        $statement->close() ;
    }
    else $incompleteSignUp = true ;   //the form is incomplete
}
//logic to log in
else if (!empty($_POST["loginUsername"]) || !empty($_POST["loginPassword"]))
{
    if (!empty($_POST["loginUsername"]) && !empty($_POST["loginPassword"]))   //all boxes have input
    {
        //search for this username
        $statement = $conn->prepare('SELECT * FROM user WHERE username = ?') ;
        $statement->bind_param('s', $username) ;
        $username = sanitizeMySQL($conn, $_POST['loginUsername']) ;   //sanitize input
        $statement->execute() ;
        $result = $statement->get_result() ;
        $statement->close() ;
        
        if ($result)    //if statement goes through
        {
            if ($result->num_rows)     //username exists
            {
                $user = $result->fetch_array(MYSQLI_ASSOC) ;    //get user from DB
                //check password
                if (password_verify(sanitizeMySQL($conn, $_POST['loginPassword']), $user['password']))
                    $_SESSION['username'] = $_POST["loginUsername"] ;   //password matches, logged in
                    else $invalidCombination = true ;   //password doesn't match
            }
            else $invalidCombination = true ;   //no such username
            
            $result->close() ;
        }
        else $retrieveLoginError = true ;   //retrieve error
    }
    else $incompleteLogin = true ;  //form is incomplete
}
//logic to upload a file
else if (!empty($_POST['content_name']) || !empty($_FILES['file_content']['tmp_name']))
{
    if (!empty($_POST['content_name']) && $_FILES['file_content']['tmp_name'])   //all boxes have input
    {
        if ($_FILES['file_content']['type'] == 'text/plain') //check file type
        {
            //check if this file name was already taken
            $statement = $conn->prepare('SELECT content_name FROM content WHERE username = ?') ;
            $statement->bind_param('s', $username) ;
            $username = sanitizeMySQL($conn, $_SESSION['username']) ;   //sanitize input
            $statement->execute() ;
            $result = $statement->get_result() ;
            
            if ($result)    //if statement goes through
            {
                $found = false ;    //flag to find existed file
                for ($i = 0; $i < $result->num_rows; $i++)  //go through list of file names
                {
                    $result->data_seek($i) ;
                    $row = $result->fetch_array(MYSQLI_NUM) ;
                    if ($row[0] == sanitizeMySQL($conn, $_POST['content_name']))    //if find file with the same name
                        $found = true ;
                }
                
                if (!$found) //if no such file name exists
                {
                    //insert a file into the database
                    $statement = $conn->prepare('INSERT INTO content VALUES(?,?,?)') ;
                    $statement->bind_param('sss', $username, $content_name, $file_content) ;
                    
                    //sanitize user inputs
                    $username = sanitizeMySQL($conn, $_SESSION['username']) ;
                    $content_name = sanitizeMySQL($conn, $_POST['content_name']) ;
                    $file_content = sanitizeMySQL($conn, file_get_contents($_FILES['file_content']['tmp_name'])) ;
                    $statement->execute() ;
                    
                    if ($statement->affected_rows) $fileAdded = true ;
                    else $insertFileError = true ;  //insert error
                }
                else $filenameExist = true ;    //duplicate file name
                
                $result->close() ;
            }
            else $retrieveFileError = true ;    //retrieve error
            
            $statement->close() ;
        }
        else $invalidFile = true ;  //wrong file type
    }
    else $incompleteFile = true ;  //form is incomplete
}
//logic to log out
else if (!empty($_POST["logout"]) && $_POST["logout"] == "yes") destroySession() ;

//if there is no session = no authentication = no active user
if (empty($_SESSION['username']))
{
    //HTML for sign up form
    echo <<<_SIGN_UP
<title>Welcome to Midterm 2</title>
<form action="midterm2.php" method="post"><pre>
--------------------------------------------SIGN UP--------------------------------------------

Don't have an account? Sign up now for free!
Username <input type="text" name="signUpUsername">
Password <input type="text" name="signUpPassword">
<input type="submit" value="Sign Up">

</pre></form>
_SIGN_UP;
    
    //handle errors
    if (isset($incompleteSignUp)) echo "Please fill all fields<br><br>" ;
    else if (isset($retrieveLoginError)) mysqlError($RETRIEVE_ERROR) ;
    else if (isset($nameTaken)) echo "This username has been taken, please choose another one<br><br>" ;
    else if (isset($insertSignupError)) mysqlError($INSERT_ERROR) ;
    
    //HTML for login form
    echo <<<_LOGIN
<form action="midterm2.php" method="post"><pre>
--------------------------------------------LOG IN--------------------------------------------

Already a member? Log in here.
Username <input type="text" name="loginUsername">
Password <input type="text" name="loginPassword">
<input type="submit" value="Log In">

</pre></form>
_LOGIN;
    
    //handle errors
    if (isset($incompleteLogin)) echo "Please fill all fields<br><br>" ;
    else if (isset($retrieveSignUpError)) mysqlError($RETRIEVE_ERROR) ;
    else if (isset($invalidCombination)) echo "Invalid username/password combination<br><br>" ;
}
//session active = user logged in
else
{
    //HTML for file submission form
    echo <<<_FILE_SUBMISSION
<title>{$_SESSION['username']}'s Dashboard</title>
<form action="midterm2.php" method="post" enctype='multipart/form-data'><pre>
Welcome, {$_SESSION['username']}!

-----------------------------------------UPLOAD A FILE-----------------------------------------

Enter filename <input type="text" name="content_name">

Select a .txt file <input type='file' name='file_content'> <input type="submit" value="Upload">

</pre></form>
_FILE_SUBMISSION;
    
    //handle errors
    if (isset($incompleteFile)) echo "Please fill all fields<br><br>" ;
    else if (isset($invalidFile)) echo "Only .txt file is accepted<br><br>" ;
    else if (isset($retrieveFileError)) mysqlError($RETRIEVE_ERROR) ;
    else if (isset($filenameExist)) echo "This filename already exists in your account,
                                            please choose another one<br><br>" ;
    else if (isset($insertFileError)) mysqlError($INSERT_ERROR) ;
    else if (isset($fileAdded)) echo "File uploaded<br><br>" ;
    else echo "Please fill all fields<br><br>" ;
    
    //HTML for log out
    echo <<<_LOGOUT
<form action="midterm2.php" method="post">
<input type="hidden" name="logout" value="yes">
<input type="submit" value="Log Out"></form>
_LOGOUT;
    
    echo "<pre>
        
-----------------------------------------UPLOADED FILES-----------------------------------------
        
</pre>" ;
    
    //search for files belonging to this user
    $statement = $conn->prepare('SELECT * FROM content WHERE username = ?') ;
    $statement->bind_param('s', $username) ;
    $username = sanitizeMySQL($conn, $_SESSION['username']) ;   //sanitize input
    $statement->execute() ;
    $result = $statement->get_result() ;
    $statement->close() ;
    
    if ($result)    //if query goes through
    {
        if ($result->num_rows)  //display content of the database
        {
            for ($i = 0; $i < $result->num_rows; $i++)
            {
                $result->data_seek($i) ;
                $row = $result->fetch_array(MYSQLI_ASSOC) ;
                echo "File Name: ".$row['content_name']."<br>" ;
                echo "Content:<pre>".$row['file_content']."</pre>" ;
                echo "--------------------------------------------------------------------------------<br>" ;
            }
        }
        else echo "You haven't uploaded anything" ;
        
        $result->close() ;
    }
    else mysqlError($RETRIEVE_ERROR) ;  //retrieve error
}

$conn->close() ;

/*
 * Destroy any info from session and its cookie
 */
function destroySession()
{
    @session_start() ;
    $_SESSION = array() ;	// delete all information in $_SESSION
    setcookie(session_name(), '', time() - 2592000, '/') ;  // delete the cookie associated with this session
    session_destroy();
}

/*
 * Display sorry message when an error happens.
 * @param $errorCode a number indicating error's type
 */
function mysqlError($errorCode)
{
    echo "<img src='https://wompampsupport.azureedge.net/fetchimage?siteId=7575&v=2&jpgQuality=100&width=700&url=https%3A%2F%2Fi.kym-cdn.com%2Fentries%2Ficons%2Ffacebook%2F000%2F028%2F692%2Fcat.jpg'>" ;
    
    global $FATAL_ERROR, $INSERT_ERROR, $RETRIEVE_ERROR ;
    switch ($errorCode)
    {
        case $FATAL_ERROR:
            echo "<br><br>Our service is down at the moment. We are sorry for the inconvenience.<br>" ;
            echo "Please try another time.<br><br>" ;
            break ;
        case $INSERT_ERROR:
            echo "<br><br>Your input can't be registered with us at the moment. Please try again.<br><br>" ;
            break ;
        case $RETRIEVE_ERROR:
            echo "<br><br>The archive can't be accessed at the moment. Please reload the page.<br><br>" ;
            break ;
    }
}

/*
 * Sanitize a string: strip all slashes, tags, and HTML entities.
 * @param $str the string that needs sanitizing
 * @return the sanitized string
 */
function sanitizeString($str)
{
    $str = stripslashes($str) ;
    $str = strip_tags($str) ;
    return htmlentities($str);
}

/*
 * Sanitize a string to be used in a MySQL query.
 * @param $conn a mysqli object
 * @param $str the string that needs sanitizing
 * @return the sanitized string
 */
function sanitizeMySQL($conn, $str)
{
    $str = $conn->real_escape_string($str) ;
    return sanitizeString($str);
}
?>