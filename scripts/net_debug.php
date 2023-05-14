<?php

// Disable warnings.
error_reporting(E_ERROR | E_PARSE);

// Settings.
$MAX_PORT = 65535;

// Return true if a str is a valid IPv6.
function is_ipv6($ip)
{
   if ( false === filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) )
   {
       return false;
   }
   else
   {
       return true;
   }
}

// Basic API for testing network services.
$action = $_GET['action'] ?? '';
switch($action)
{
    /*
        The purpose of the 'hello' API method is to send 'hello' to
        a remote machine. This is because some protocols don't let you
        send back messages to yourself to test that communication is possible.
        So you need to use a third-party to do this. Any host:port is
        accepted but to limit abuse it still only sends 'hello'.
    */
    case 'hello':
        // Control timeout (TCP only.)
        $timeout = $_GET['timeout'] ?? 2;
        if(!is_numeric($timeout))
        {
            die("Invalid timeout");
        }
        
        // Check transport protocol.
        $proto = $_GET['proto'] ?? 'udp';
        if(!in_array($proto, array('tcp', 'udp')))
        {
            die("Invalid protocol.");
        }
        
        // Check chosen port.
        $alt_port = ($_SERVER['REMOTE_PORT'] + 1) % ($MAX_PORT + 1);
        $port = $_GET['port'] ?? $alt_port;
        if(!is_numeric($port))
        {
            die("Invalid port.");
        }
        
        // Format host properly for IPv6.
        $host = $_GET['host'] ?? $_SERVER['REMOTE_ADDR'];
        if(is_ipv6($host))
        {
            $host = '[' . $host . ']';
        }
        
        // Open a new socket.
        $target = $proto . "://" . $host;
        $sock = fsockopen($target, (int) $port, $errno, $errstr, (int) $timeout);
        if(!$sock)
        {
            die("fsockopen error: $errno - $errstr");
        }
        
        // Send hello down socket.
        fwrite($sock, "hello");
        fclose($sock);
        
    default:
        die("0");
        break;
}

?>