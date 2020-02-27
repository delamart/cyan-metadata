<?php

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Nahid\JsonQ\Jsonq;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;

require __DIR__ . '/../vendor/autoload.php';
$DATA_DIR = __DIR__ . '/../data';

$app = AppFactory::create();

$app->get('/', function (Request $request, Response $response, $args) {
    $response->getBody()->write("OK");
    return $response;    
});

$app->get('/metadata/instance[/{path:.*}]', function (Request $request, Response $response, $args) use ($DATA_DIR) {
    $path = $args['path'];
    $jsonq = new JsonQ($DATA_DIR . '/compute/example.json');
    if($path) {
        $jsonq = $jsonq->from(strtr($path,'/','.'));
    }
    $payload = $jsonq->toJson();
    if(empty(json_decode($payload))) { return $response->withStatus(404,'path not found'); }

    $response->getBody()->write($payload);

    return $response->withHeader('Content-Type', 'application/json');
});

$app->get('/metadata/identity/oauth2/token', function (Request $request, Response $response, $args) use ($DATA_DIR) {

    $params = $request->getServerParams();
    $ip = $params['REMOTE_ADDR'];
    $hostname = gethostbyaddr($ip);
    
    $url = "https://management.local/";

    $algorithmManager = new AlgorithmManager([ new RS256() ]);
    $jwsBuilder = new JWSBuilder($algorithmManager);
    $serializer = new CompactSerializer(); // The serializer

    $jwk = JWKFactory::createFromKeyFile( $DATA_DIR . '/keys/cyan.key' );
    $thumbprint= $jwk->thumbprint('sha1');

    $now = time();
    $expire = $now + 3600;

    $header = [
        "typ" => "JWT",
        "alg" => "RS256",
        "x5t" => $thumbprint,
        "kid" => $thumbprint,
    ];
    $payload = json_encode([
        "aud" => $url,
        "iss" => $url,
        "iat" => $now,
        "nbf" => $now,
        "exp" => $expire,
        //"aio" => "42NgYDjLHvrN+t9FCSk2JRvPp/M/AAA=",
        "appid" => $target,
        "appidacr" => "2",
        "idp" => $url,
        "oid" => $target,
        "sub" => $target,
        //"tid" => "d4e30a6a-7a8e-4d6d-ae8e-fd3106c4e94c",
        //"uti" => "2crAP3aHAEeKhQHEExFwAA",
        "ver" => "1.0",
        //"xms_mirid" => "/subscriptions/6b78a1f4-a858-4c94-841c-84e0464f562e/resourcegroups/rg-lab-vm/providers/Microsoft.Compute/virtualMachines/labvm"
    
    ]);
    
    $jws = $jwsBuilder
        ->create()                               // We want to create a new JWS
        ->withPayload($payload)                  // We set the payload
        ->addSignature($jwk, $header)            // We add a signature with a simple protected header
        ->build();                               // We build it
    
    $token = $serializer->serialize($jws, 0); // We serialize the signature at index 0 (we only have one signature).

    $payload = json_encode(array(
        "access_token" => $token,
        "client_id" => $target,
        "expires_in"=> "3600",
        "expires_on" => $expire,
        "ext_expires_in" => "3600",
        "not_before" => $expire,
        "resource" => $url,
        "token_type" => "Bearer"
    ));
    $response->getBody()->write($payload);
    return $response->withHeader('Content-Type', 'application/json');
});

$app->get('/metadata/scheduledevents', function (Request $request, Response $response, $args) {
});

$app->get('/metadata/attested', function (Request $request, Response $response, $args) {
});

$app->run();