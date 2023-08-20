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
        
        Todo: expect reply?
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
        
        echo($port);
        
        // Format host properly for IPv6.
        $host = $_GET['host'] ?? $_SERVER['REMOTE_ADDR'];
        if(is_ipv6($host))
        {
            $af = AF_INET6;
            $host = '[' . $host . ']';
        }
        else
        {
            $af = AF_INET;
        }
        
        // Setup bind / listen port.
        $bind = $_GET["bind"] ?? 0;
        if(!is_numeric($bind))
        {
            die('invalid bind port');
        }
        
        // Setup socket proto options.
        if($proto == "udp")
        {
            $type = SOCK_DGRAM;
            $proto = SOL_UDP;
        }
        else
        {
            $type = SOCK_STREAM;
            $proto = SOL_TCP;
        }
        
        // Create a new socket.
        $sock = socket_create($af, $type, $proto);
        
        // Bind the socket to a specific port.
        socket_bind($sock, 0, (int) $bind);
        
        // Connect the socket if it's TCP.
        if($proto == SOL_TCP)
        {
            socket_connect($sock, $host, (int) $port);
            socket_write($sock, "hello");
        }
        
        // Send hello down socket if it's UDP.
        if($proto == SOL_UDP)
        {
            $buf = "hello";
            socket_sendto($sock, $buf, strlen($buf), 0, $host, (int) $port);
        }
        
        
        $buf = '';
        $bytes_received = socket_recvfrom($sock, $buf, 65536, $host, (int) $port);
        
        // Cleanup.
        socket_close($sock);
        die($buf);
        break;
        
    case 'host':
        $version = $_GET["version"] ?? "4";
        if($version == "4")
        {
            $url = 'https://checkip.amazonaws.com';
            $b = '0:0';
        }
        else
        {
            $url = 'https://icanhazip.com/';
            $b = '[::]:0';
        }
        
        // connect to the internet using port '7000'
        $opts = array(
            'socket' => array(
                'bindto' => $b,
            ),
        );
        
        // create the context...
        $context = stream_context_create($opts);
        
        // ...and use it to fetch the data
        die(rtrim(file_get_contents($url, false, $context)));
        break;
        
    case 'mapping':
        break;
        
    default:
        die("0");
        break;
}

?>