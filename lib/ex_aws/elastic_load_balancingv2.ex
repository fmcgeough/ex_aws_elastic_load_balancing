defmodule ExAws.ElasticLoadBalancingV2 do
  @moduledoc """
  Operations on AWS ELB (Elastic Load Balancing) V2 API

  AWS Elastic Load Balancing supports three types of load balancers: Application
  Load Balancers (ALB), Network Load Balancers (NLB), and Classic Load Balancers. You can
  select a load balancer based on your application needs. This API covers the
  ALB and NLB. Classic Load Balancers are covered by the `ExAws.ElasticLoadBalancing` module.

  More information:
  * [Elastic Load Balancing User Guide][User_Guide]
  * [Elastic Load Balancing API][API_Doc]
  * [Amazon Resource Names (ARNs)][ARN_Doc]

  [User_Guide]: http://docs.aws.amazon.com/elasticloadbalancing/latest/userguide/
  [API_Doc]: http://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/
  [ARN_Doc]: http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
  """

  use ExAws.Utils,
    format_type: :xml,
    non_standard_keys: %{}

  alias ExAws.ElasticLoadBalancingV2.Parsers, as: V2Parser

  # version of the AWS API
  @version "2015-12-01"

  @typedoc """
  Information about a tag
  """
  @type tag() :: {atom(), binary()} | %{key: binary, value: binary}

  @typedoc """
  A list of `t:tag/0`
  """
  @type tags :: [tag, ...]

  @typedoc """
  The tag keys for the tags to remove.

  Length Constraints: Minimum length of 1. Maximum length of 128.

  Pattern: ^([\p{L}\p{Z}\p{N}_.:/=+\-@]*)$
  """
  @type tag_keys :: [binary, ...]

  @typedoc """
  The name of the load balancer.

  This name must be unique per region per account, can have a maximum of 32 characters,
  must contain only alphanumeric characters or hyphens, must not begin or end with
  a hyphen, and must not begin with "internal-".
  """
  @type load_balancer_name() :: binary

  @typedoc """
  Information about a load balancer attribute.
  """
  @type load_balancer_attribute :: %{
          optional(:key) => binary,
          optional(:value) => binary
        }

  @typedoc """
  Information about a target group attribute.
  """
  @type target_group_attribute() :: {key :: atom, value :: binary}

  @typedoc """
  A list of `t:target_group_attribute/0`
  """
  @type target_group_attributes() :: [target_group_attribute(), ...]

  @typedoc """
  The Amazon Resource Name (ARN) of the listener
  """
  @type listener_arn() :: binary

  @typedoc """
  The Amazon Resource Name (ARN) of the rule
  """
  @type rule_arn :: binary

  @typedoc """
  The Amazon Resource Name (ARN) of the target group
  """
  @type target_group_arn() :: binary()

  @typedoc """
  A single Amazon Resource Name (ARN)
  """
  @type resource_arn() :: binary()

  @typedoc """
  A list of `t:resource_arn/0`
  """
  @type resource_arns :: [resource_arn(), ...]

  @typedoc """
  The port on which the load balancer is listening. You can't specify a port for a Gateway Load Balancer.

  Valid Range: Minimum value of 1. Maximum value of 65535.
  """
  @type port_num() :: integer

  @typedoc """
  The rule priority

  A listener can't have multiple rules with the same priority.

  Valid Range: Minimum value of 1. Maximum value of 50000.
  """
  @type priority() :: pos_integer()

  @typedoc """
  The IP address type. Internal load balancers must use ipv4

  [Application Load Balancers] The possible values are ipv4 (IPv4 addresses),
  dualstack (IPv4 and IPv6 addresses), and dualstack-without-public-ipv4 (public
  IPv6 addresses and private IPv4 and IPv6 addresses).

  Application Load Balancer authentication supports IPv4 addresses only when
  connecting to an Identity Provider (IdP) or Amazon Cognito endpoint. Without
  a public IPv4 address the load balancer can't complete the authentication
  process, resulting in HTTP 500 errors.

  [Network Load Balancers and Gateway Load Balancers] The possible values are ipv4 (IPv4
  addresses) and dualstack (IPv4 and IPv6 addresses).

  Valid Values
  ```
  "ipv4" | "dualstack" | "dualstack-without-public-ipv4"
  ```
  """
  @type ip_address_type() :: binary

  @typedoc """
  The protocol for connections from clients to the load balancer. For Application Load
  Balancers, the supported protocols are HTTP and HTTPS. For Network Load Balancers, the
  supported protocols are TCP, TLS, UDP, and TCP_UDP. You can’t specify the UDP or
  TCP_UDP protocol if dual-stack mode is enabled. You can't specify a protocol for a
  Gateway Load Balancer.

  Valid Values
  ```
  "HTTP" | "HTTPS" | "TCP" | "TLS" | "UDP" | "TCP_UDP" | "GENEVE"
  ```
  """
  @type protocol() :: binary

  @typedoc """
  [HTTP/HTTPS protocol] The protocol version

  Specify "GRPC" to send requests to targets using gRPC. Specify "HTTP2" to send
  requests to targets using HTTP/2. The default is "HTTP1", which sends requests
  to targets using HTTP/1.1.
  """
  @type protocol_version() :: binary

  @typedoc """
  The protocol the load balancer uses when performing health checks on targets

  For Application Load Balancers, the default is HTTP. For Network Load Balancers
  and Gateway Load Balancers, the default is TCP. The TCP protocol is not supported
  for health checks if the protocol of the target group is HTTP or HTTPS. The
  GENEVE, TLS, UDP, and TCP_UDP protocols are not supported for health checks.

  Valid Values
  ```
  "HTTP" | "HTTPS" | "TCP" | "TLS" | "UDP" | "TCP_UDP" | "GENEVE"
  ```
  """
  @type health_check_protocol() :: binary()

  @typedoc """
  The protocol the load balancer uses when performing health checks on targets

  For Application Load Balancers, the default is HTTP. For Network Load Balancers
  and Gateway Load Balancers, the default is TCP. The TCP protocol is not supported
  for health checks if the protocol of the target group is HTTP or HTTPS. The
  GENEVE, TLS, UDP, and TCP_UDP protocols are not supported for health checks.
  """
  @type health_check_port() :: binary()

  @typedoc """
  The number of consecutive health check successes required before considering
  a target healthy

  The range is 2-10. If the target group protocol is TCP, TCP_UDP, UDP, TLS,
  HTTP or HTTPS, the default is 5. For target groups with a protocol of GENEVE,
  the default is 5. If the target type is lambda, the default is 5.

  Valid Range
  ```
  Minimum value of 2. Maximum value of 10.
  ```
  """
  @type healthy_threshold_count() :: pos_integer()

  @typedoc """
  Indicates whether health checks are enabled

  If the target type is lambda, health checks are disabled by default
  but can be enabled. If the target type is instance, ip, or alb,
  health checks are always enabled and can't be disabled.
  """
  @type health_check_enabled() :: boolean()

  @typedoc """
  The number of consecutive health check failures required before considering the target unhealthy.

  ```
  Valid Range: Minimum value of 2. Maximum value of 10.
  ```
  """
  @type unhealthy_threshold_count() :: pos_integer()

  @typedoc """
  For Application Load Balancers, you can specify values between 200
  and 499, with the default value being 200

  You can specify multiple values (for example, "200,202") or a range
  of values (for example, "200-299").

  For Network Load Balancers, you can specify values between 200 and
  599, with the default value being 200-399. You can specify multiple
  values (for example, "200,202") or a range of values (for example, "200-299").

  For Gateway Load Balancers, this must be "200–399".

  Note that when using shorthand syntax, some values such as commas need to be escaped
  """
  @type http_code() :: binary()

  @typedoc """
  You can specify values between 0 and 99.
  You can specify multiple values (for example, "0,1") or a range of
  values (for example, "0-5"). The default value is 12.
  """
  @type grpc_code() :: binary()

  @typedoc """
  The codes to use when checking for a successful response from a target

  If the protocol version is gRPC, these are gRPC codes. Otherwise, these are HTTP codes.
  """
  @type matcher() ::
          [{:grpc_code, grpc_code()}, {:http_code, http_code()}]
          | %{
              optional(:grpc_code) => grpc_code(),
              optional(:http_code) => http_code()
            }

  @typedoc """
  The name of the target group.

  This name must be unique per region per account, can have a maximum of 32
  characters, must contain only alphanumeric characters or hyphens, and must
  not begin or end with a hyphen.
  """
  @type target_group_name() :: binary

  @typedoc """
  The identifier of the virtual private cloud (VPC)

  If the target is a Lambda function, this parameter does not apply. Otherwise, this
  parameter is required.
  """
  @type vpc_id() :: binary

  @typedoc """
  The type of target that you must specify when registering targets with this target group

  You can't specify targets for a target group using more than one target type.

  - "instance" - Register targets by instance ID. This is the default value.
  - "ip" - Register targets by IP address. You can specify IP addresses from the
           subnets of the virtual private cloud (VPC) for the target group, the
           RFC 1918 range (10.0.0.0/8, 172.16.0.0/12, and 192.168.0.0/16), and
           the RFC 6598 range (100.64.0.0/10). You can't specify publicly routable
           IP addresses.
  - "lambda" - Register a single Lambda function as a target.
  - "alb" - Register a single Application Load Balancer as a target.

  Valid Values
  ```
  "instance" | "ip" | "lambda" | "alb"
  ```
  """
  @type target_type() :: binary

  @typedoc """
  The approximate amount of time, in seconds, between health checks of an individual target

  The range is 5-300. If the target group protocol is TCP, TLS, UDP, TCP_UDP, HTTP or HTTPS,
  the default is 30 seconds. If the target group protocol is GENEVE, the default is 10 seconds.
  If the target type is lambda, the default is 35 seconds.

  Valid Range
  ```
  Minimum value of 5. Maximum value of 300
  ```
  """
  @type health_check_interval_seconds() :: pos_integer()

  @typedoc """
  The amount of time, in seconds, during which no response from
  a target means a failed health check

  The range is 2–120 seconds. For target groups with a protocol of HTTP,
  the default is 6 seconds. For target groups with a protocol of TCP, TLS
  or HTTPS, the default is 10 seconds. For target groups with a protocol
  of GENEVE, the default is 5 seconds. If the target type is lambda, the
  default is 30 seconds.


  Valid Range
  ```
  Minimum value of 2. Maximum value of 120.
  ```
  """
  @type health_check_timeout_seconds() :: pos_integer()

  @typedoc """
  [HTTP/HTTPS health checks] The destination for health checks on the targets

  - [HTTP1 or HTTP2 protocol version] The ping path. The default is /.
  - [GRPC protocol version] The path of a custom health check method with the
  format /package.service/method. The default is "/AWS.ALB/healthcheck".

  Length Constraints
  ```
  Minimum length of 1. Maximum length of 1024.
  ```
  """
  @type health_check_path() :: binary

  @typedoc """
  The Amazon Resource Name (ARN) of the load balancer
  """
  @type load_balancer_arn() :: binary

  @typedoc """
  A list of `t:load_balancer_arn/0`
  """
  @type load_balancer_arns() :: [load_balancer_arn(), ...]

  @typedoc """
  The type of revocation file.

  Valid Values:
  ```
  "CRL"
  ```
  """
  @type revocation_type() :: binary

  @typedoc """
  The Amazon S3 bucket
  """
  @type s3_bucket() :: binary

  @typedoc """
  The Amazon S3 path
  """
  @type s3_key() :: binary

  @typedoc """
  The Amazon S3 object version
  """
  @type s3_object_version() :: binary

  @typedoc """
  The Amazon Resource Name (ARN) of the trust store.
  """
  @type trust_store_arn() :: binary

  @typedoc """
  The revocation ID of the revocation file
  """
  @type revocation_id() :: integer()

  @typedoc """
  The maximum number of results to return with this call

  Valid Range: Minimum value of 1. Maximum value of 400.
  """
  @type page_size() :: pos_integer()

  @typedoc """
  The marker for the next set of results

  You received this marker from a previous call.
  """
  @type marker() :: binary()

  @typedoc """
  Information about a revocation file.
  """
  @type revocation_content() ::
          [
            {:revocation_type, revocation_type()},
            {:s3_bucket, s3_bucket()},
            {:s3_key, s3_key()},
            {:s3_object_version, s3_object_version()}
          ]
          | %{
              optional(:revocation_type) => revocation_type(),
              optional(:s3_bucket) => s3_bucket(),
              optional(:s3_key) => s3_key(),
              optional(:s3_object_version) => s3_object_version()
            }

  @typedoc """
  A list of `t:revocation_content/0`
  """
  @type revocation_contents :: [revocation_content(), ...]

  @typedoc """
  The type of action.

  Valid Values
  ```
  "forward" | "authenticate-oidc" | "authenticate-cognito" | "redirect" | "fixed-response"
  ```
  """
  @type action_type() :: binary

  @typedoc """
  Request parameters to use when integrating with Amazon Cognito to authenticate users.
  """
  @type authenticate_cognito_action_config :: %{
          required(:user_pool_arn) => binary,
          required(:user_pool_client_id) => binary,
          required(:user_pool_domain) => binary,
          optional(:session_cookie_name) => binary,
          optional(:scope) => binary,
          optional(:session_timeout) => integer,
          optional(:authentication_request_extra_params) => %{optional(binary) => binary},
          optional(:on_unauthenticated_request) => binary,
          optional(:use_existing_client_secret) => boolean
        }

  @typedoc """
  Request parameters when using an identity provider (IdP) that is compliant with OpenID
  Connect (OIDC) to authenticate users.
  """
  @type authenticate_oidc_action_config :: %{
          required(:issuer) => binary,
          required(:authorization_endpoint) => binary,
          required(:token_endpoint) => binary,
          required(:user_info_endpoint) => binary,
          required(:client_id) => binary,
          optional(:client_secret) => binary,
          optional(:session_cookie_name) => binary,
          optional(:scope) => binary,
          optional(:session_timeout) => integer,
          optional(:authentication_request_extra_params) => %{optional(binary) => binary},
          optional(:on_unauthenticated_request) => binary,
          optional(:use_existing_client_secret) => boolean
        }

  @typedoc """
  The HTTP response code (2XX, 4XX, or 5XX).

  Pattern: `^(2|4|5)\d\d$`
  """
  @type fixed_response_action_status_code() :: binary()

  @typedoc """
  The content type

  Valid Values
  ```
  "text/plain" | "text/css" | "text/html" | "application/javascript" | "application/json"
  ```

  Length Constraints
  ```
  Minimum length of 0. Maximum length of 32.
  ```
  """
  @type fixed_response_action_content_type() :: binary()

  @typedoc """
  The message body

  Length Constraints
  ```
  Minimum length of 0. Maximum length of 1024.
  ```
  """
  @type fixed_response_action_message() :: binary()

  @typedoc """
  Information about an action that returns a custom HTTP response
  """
  @type fixed_response_config() ::
          [
            {:status_code, fixed_response_action_status_code()},
            {:content_type, fixed_response_action_content_type()},
            {:message_body, fixed_response_action_message()}
          ]
          | %{
              required(:status_code) => fixed_response_action_status_code(),
              optional(:content_type) => fixed_response_action_content_type(),
              optional(:message_body) => fixed_response_action_message()
            }

  @typedoc """
  Information about the target group stickiness for a rule.
  """
  @type target_group_stickiness_config() :: %{
          optional(:enabled) => boolean,
          optional(:duration_seconds) => integer
        }

  @typedoc """
  Information about how traffic will be distributed between multiple target groups
  in a forward rule
  """
  @type target_group_tuple() :: %{
          optional(:target_group_arn) => target_group_arn(),
          optional(:weight) => integer
        }

  @typedoc """
  Information about a forward action.
  """
  @type forward_action_config() :: %{
          optional(:target_groups) => [target_group_tuple()],
          optional(:target_group_stickiness_config) => target_group_stickiness_config()
        }

  @typedoc """
  The order for the action

  This value is required for rules with multiple actions. The action
  with the lowest value for order is performed first.

  Valid Range: Minimum value of 1. Maximum value of 50000.
  """
  @type order_action :: pos_integer()

  @typedoc """
  Information about a redirect action

  A URI consists of the following components: protocol://hostname:port/path?query. You must modify
  at least one of the following components to avoid a redirect loop: protocol, hostname, port, or
  path. Any components that you do not modify retain their original values.

  You can reuse URI components using the following reserved keywords:

  - "\#{protocol}"
  - "\#{host}"
  - "\#{port}"
  - "\#{path}" (the leading "/" is removed)
  - "\#{query}"

  For example, you can change the path to "/new/\#{path}", the hostname to "example.\#{host}", or the
  query to "\#{query}&value=xyz".
  """
  @type redirect_action_config :: %{
          optional(:protocol) => binary,
          optional(:port) => binary,
          optional(:host) => binary,
          optional(:path) => binary,
          optional(:query) => binary,
          required(:status_code) => binary
        }

  @typedoc """
  Information about an action.

  Each rule must include exactly one of the following types of actions: forward, fixed-response,
  or redirect, and it must be the last action to be performed.
  """
  @type action() ::
          [
            type: action_type(),
            authenticate_cognito_config: authenticate_cognito_action_config(),
            authenticate_oidc_config: authenticate_oidc_action_config(),
            fixed_response_config: fixed_response_config(),
            forward_config: forward_action_config(),
            order: order_action(),
            redirect_config: redirect_action_config(),
            target_group_arn: target_group_arn()
          ]
          | %{
              optional(:type) => action_type(),
              optional(:authenticate_cognito_config) => authenticate_cognito_action_config(),
              optional(:authenticate_oidc_config) => authenticate_oidc_action_config(),
              optional(:fixed_response_config) => fixed_response_config(),
              optional(:forward_config) => forward_action_config(),
              optional(:order) => order_action(),
              optional(:redirect_config) => redirect_action_config(),
              optional(:target_group_arn) => target_group_arn()
            }

  @typedoc """
  A list of `t:action/0`
  """
  @type actions() :: [action, ...]

  @typedoc """
  The Amazon Resource Name (ARN) of the certificate.
  """
  @type certificate_arn :: binary

  @typedoc """
  [HTTPS and TLS listeners] The security policy that defines which protocols and ciphers are supported.

  For more information, see Security policies in the Application Load Balancers
  Guide and Security policies in the Network Load Balancers Guide.
  """
  @type ssl_policy() :: binary

  @typedoc """
  Information about an SSL server certificate.
  """
  @type certificate ::
          [
            {:certificate_arn, certificate_arn()},
            {:is_default, boolean}
          ]
          | %{
              optional(:certificate_arn) => certificate_arn(),
              optional(:is_default) => boolean
            }

  @typedoc """
  A list of `t:certificate/0`
  """
  @type certificates() :: [certificate(), ...]

  @typedoc """
  Information about a host header condition.

  - regex_values - The regular expressions to compare against the host header. The maximum
    length of each string is 128 characters.
  - values - The host names. The maximum length of each string is 128 characters. The
    comparison is case insensitive. The following wildcard characters are
    supported: * (matches 0 or more characters) and ? (matches exactly 1 character). You
    must include at least one "." character. You can include only alphabetical characters
    after the final "." character.
  """
  @type host_header_config() ::
          [
            {:regex_values, [binary(), ...]},
            {:values, [binary(), ...]}
          ]
          | %{
              optional(:regex_values) => [binary(), ...],
              optional(:values) => [binary(), ...]
            }

  @typedoc """
  [TLS listeners] The name of the Application-Layer Protocol Negotiation (ALPN) policy.

  You can specify one policy name.

  Valid Values
  ```
  "HTTP1Only" | "HTTP2Only" | "HTTP2Optional" | "HTTP2Preferred" | "None"
  ```

  For more information, see ALPN policies in the Network Load Balancers Guide.
  """
  @type alpn_policy() :: binary()

  @typedoc """
  The IDs of the security groups.
  """
  @type security_groups() :: [binary(), ...]

  @typedoc """
  The type of load balancer. The default is "application".

  Valid Values
  ```
  "application" | "network" | "gateway"
  ```
  """
  @type load_balancer_type() :: binary()

  @typedoc """
  The nodes of an Internet-facing load balancer have public IP addresses.
  The DNS name of an Internet-facing load balancer is publicly resolvable
  to the public IP addresses of the nodes. Therefore, Internet-facing load
  balancers can route requests from clients over the internet.

  The nodes of an internal load balancer have only private IP addresses.
  The DNS name of an internal load balancer is publicly resolvable to the
  private IP addresses of the nodes. Therefore, internal load balancers
  can route requests only from clients with access to the VPC for the load balancer.

  The default is an Internet-facing load balancer.

  You can't specify a scheme for a Gateway Load Balancer.

  Valid Values
  ```
  "internet-facing" | "internal"
  ```
  """
  @type load_balancer_scheme() :: binary()

  @typedoc """
  Information about a target.
  """
  @type target_description :: %{
          required(:id) => binary,
          optional(:port) => port_num(),
          optional(:availability_zone) => binary
        }

  @typedoc """
  A list of `t:target_description/0`
  """
  @type target_descriptions :: [target_description()]

  @typedoc """
  Information about a subnet mapping
  """
  @type subnet_mapping :: [
          subnet_id: binary,
          allocation_id: binary
        ]

  @typedoc """
  The values "on" and "off"

  Valid Values:
  ```
  "on" | "off"
  ```
  """
  @type on_or_off() :: binary()

  @typedoc """
  The client certificate handling method

  Valid Values:
  ```
  "off" | "passthrough" | "verify"
  ```
  """
  @type mode() :: binary()

  @typedoc """
  Indicates a shared trust stores association status.

  Valid Values:
  ```
  "active" | "removed"
  ```
  """
  @type trust_store_association_status() :: binary()

  @typedoc """
  Information about the mutual authentication attributes of a listener

  """
  @type mutual_authentication_attributes() :: %{
          optional(:advertise_trust_store_ca_names) => on_or_off(),
          optional(:ignore_client_certificate_expiry) => boolean(),
          optional(:mode) => mode(),
          optional(:trust_store_arn) => trust_store_arn(),
          optional(:trust_store_association_status) => trust_store_association_status()
        }

  @typedoc """
  The IDs of the public subnets. You can specify only one subnet
  per Availability Zone

  You must specify either subnets or subnet mappings.

  - [Application Load Balancers] You must specify subnets from at least
    two Availability Zones. You can't specify Elastic IP addresses for your subnets.
  - [Application Load Balancers on Outposts] You must specify one Outpost subnet.
  - [Application Load Balancers on Local Zones] You can specify subnets from one
    or more Local Zones.
  - [Network Load Balancers] You can specify subnets from one or more Availability
    Zones. You can specify one Elastic IP address per subnet if you need static IP
    addresses for your internet-facing load balancer. For internal load balancers,
    you can specify one private IP address per subnet from the IPv4 range of the
    subnet. For internet-facing load balancer, you can specify one IPv6 address
    per subnet.
  - [Gateway Load Balancers] You can specify subnets from one or more Availability
    Zones.
  """
  @type subnets() :: [binary(), ...]

  @typedoc """
  [Application Load Balancers on Outposts] The ID of the customer-owned address pool (CoIP pool)

  Length Constraints: Maximum length of 256.
  Pattern: `^(ipv4pool-coip-)[a-zA-Z0-9]+$`
  """
  @type customer_owned_ipv4_pool() :: binary()

  @typedoc """
  [Network Load Balancers with UDP listeners] Indicates whether to
  use an IPv6 prefix from each subnet for source NAT.

  The IP address type must be dualstack. The default value is "off".

  Valid Values:
  ```
  "on" | "off"
  ```
  """
  @type enable_prefix_for_ipv6_source_nat() :: binary()

  @typedoc """
  An IPAM pool is a collection of IP address CIDRs

  IPAM pools enable you to organize your IP addresses according to your
  routing and security needs.

  Length Constraints: Maximum length of 1000.
  Pattern: `^(ipam-pool-)[a-zA-Z0-9]+$`
  """
  @type ipv4_ipam_pool_id() :: binary()

  @type i_pam_pools() ::
          [ipv4_ipam_pool_id: ipv4_ipam_pool_id()]
          | %{
              optional(:ipv4_ipam_pool_id) => ipv4_ipam_pool_id()
            }

  @typedoc """
  The name of the trust store.

  Length Constraints: `Minimum length of 1. Maximum length of 32.`
  Pattern: `^([a-zA-Z0-9]+-)*[a-zA-Z0-9]+$`
  """
  @type trust_store_name() :: binary()

  @typedoc """
  The Amazon S3 bucket for the ca certificates bundle.
  """
  @type ca_certificates_bundle_s3_bucket() :: binary()

  @typedoc """
  The Amazon S3 path for the ca certificates bundle.
  """
  @type ca_certificates_bundle_s3_key() :: binary()

  @typedoc """
  The Amazon S3 object version for the ca certificates bundle

  If undefined the current version is used.
  """
  @type ca_certificates_bundle_s3_object_version() :: binary()

  @type create_trust_store_opts() ::
          [
            {:ca_certificates_bundle_s3_object_version, ca_certificates_bundle_s3_object_version()},
            {:tags, tags()}
          ]
          | %{
              optional(:ca_certificates_bundle_s3_object_version) => ca_certificates_bundle_s3_object_version(),
              optional(:tags) => tags()
            }

  @typedoc """
  Optional parameters for `add_trust_store_revocations/2`.
  """
  @type add_trust_store_revocations_opts() ::
          [
            {:revocation_contents, revocation_contents()}
          ]
          | %{
              optional(:revocation_contents) => revocation_contents()
            }

  @typedoc """
  Optional parameters for `describe_trust_store_associations/2`.
  """
  @type describe_trust_store_associations_opts() ::
          [
            {:page_size, page_size()},
            {:marker, marker()}
          ]
          | %{
              optional(:page_size) => page_size(),
              optional(:marker) => marker()
            }

  @typedoc """
  Optional parameters for `describe_trust_store_revocations/2`.
  """
  @type describe_trust_store_revocations_opts() ::
          [
            {:page_size, page_size()},
            {:marker, marker()},
            {:revocation_ids, [revocation_id(), ...]}
          ]
          | %{
              optional(:page_size) => page_size(),
              optional(:marker) => marker(),
              optional(:revocation_ids) => [revocation_id(), ...]
            }

  @typedoc """
  Optional parameters for `describe_trust_stores/1`.
  """
  @type describe_trust_stores_opts() ::
          [
            {:page_size, page_size()},
            {:marker, marker()},
            {:names, [trust_store_name(), ...]},
            {:trust_store_arns, [trust_store_arn(), ...]}
          ]
          | %{
              optional(:page_size) => page_size(),
              optional(:marker) => marker(),
              optional(:names) => [trust_store_name(), ...],
              optional(:trust_store_arns) => [trust_store_arn(), ...]
            }

  @typedoc """
  Optional parameters for `create_listener/3`.
  """
  @type create_listener_opts ::
          [
            {:alpn_policy, [alpn_policy()]},
            {:certificates, certificates()},
            {:mutual_authentication, mutual_authentication_attributes()},
            {:port, port_num()},
            {:protocol, protocol()},
            {:ssl_policy, ssl_policy()},
            {:tags, tags()}
          ]
          | %{
              optional(:alpn_policy) => [alpn_policy()],
              optional(:certificates) => certificates(),
              optional(:mutual_authentication) => mutual_authentication_attributes(),
              optional(:port) => port_num(),
              optional(:protocol) => protocol(),
              optional(:ssl_policy) => ssl_policy(),
              optional(:tags) => tags()
            }

  @typedoc """
  Optional parameters for `create_listener/5`.
  """
  @type deprecated_create_listener_opts ::
          [
            {:alpn_policy, [alpn_policy()]},
            {:certificates, certificates()},
            {:mutual_authentication, mutual_authentication_attributes()},
            {:ssl_policy, ssl_policy()},
            {:tags, tags()}
          ]
          | %{
              optional(:alpn_policy) => [alpn_policy()],
              optional(:certificates) => certificates(),
              optional(:mutual_authentication) => mutual_authentication_attributes(),
              optional(:ssl_policy) => ssl_policy(),
              optional(:tags) => tags()
            }

  @typedoc """
  Optional parameters for `create_load_balancer/2`.
  """
  @type create_load_balancer_opts ::
          [
            customer_owned_ipv4_pool: customer_owned_ipv4_pool(),
            enable_prefix_for_ipv6_source_nat: enable_prefix_for_ipv6_source_nat(),
            ip_address_type: ip_address_type(),
            i_pam_pools: i_pam_pools(),
            scheme: load_balancer_scheme(),
            security_groups: [binary(), ...],
            subnets: subnets(),
            subnet_mappings: [subnet_mapping(), ...],
            tags: tags(),
            type: load_balancer_type()
          ]
          | %{
              optional(:customer_owned_ipv4_pool) => customer_owned_ipv4_pool(),
              optional(:enable_prefix_for_ipv6_source_nat) => enable_prefix_for_ipv6_source_nat(),
              optional(:ip_address_type) => ip_address_type(),
              optional(:i_pam_pools) => i_pam_pools(),
              optional(:scheme) => load_balancer_scheme(),
              optional(:security_groups) => [binary(), ...],
              optional(:subnets) => subnets(),
              optional(:subnet_mappings) => [subnet_mapping, ...],
              optional(:tags) => tags(),
              optional(:type) => load_balancer_type()
            }

  @typedoc """
  Optional parameters for `create_target_group/3`.
  """
  @type create_target_group_opts ::
          [
            health_check_enabled: health_check_enabled(),
            health_check_interval_seconds: health_check_interval_seconds(),
            health_check_path: health_check_path(),
            health_check_port: health_check_port(),
            health_check_protocol: health_check_protocol(),
            health_check_timeout_seconds: health_check_timeout_seconds(),
            healthy_threshold_count: healthy_threshold_count(),
            ip_address_type: ip_address_type(),
            matcher: matcher(),
            port: port_num(),
            protocol: protocol(),
            protocol_version: protocol_version(),
            tags: tags(),
            target_type: target_type(),
            unhealthy_threshold_count: unhealthy_threshold_count(),
            vpc_id: vpc_id()
          ]
          | %{
              optional(:health_check_enabled) => health_check_enabled(),
              optional(:health_check_interval_seconds) => health_check_interval_seconds(),
              optional(:health_check_path) => health_check_path(),
              optional(:health_check_port) => health_check_port(),
              optional(:health_check_protocol) => health_check_protocol(),
              optional(:health_check_timeout_seconds) => health_check_timeout_seconds(),
              optional(:healthy_threshold_count) => healthy_threshold_count(),
              optional(:ip_address_type) => ip_address_type(),
              optional(:matcher) => matcher(),
              optional(:port) => port_num(),
              optional(:protocol) => protocol(),
              optional(:protocol_version) => protocol_version(),
              optional(:tags) => tags(),
              optional(:target_type) => target_type(),
              optional(:unhealthy_threshold_count) => unhealthy_threshold_count(),
              optional(:vpc_id) => vpc_id()
            }

  @typedoc """
  Optional parameters for `modify_listener/2`.
  """
  @type modify_listener_opts ::
          [
            port: port_num(),
            protocol: protocol(),
            ssl_policy: ssl_policy(),
            certificates: certificates(),
            default_actions: actions()
          ]
          | %{
              optional(:port) => port_num(),
              optional(:protocol) => protocol(),
              optional(:ssl_policy) => ssl_policy(),
              optional(:certificates) => certificates(),
              optional(:default_actions) => actions()
            }

  @typedoc """
  Information about a condition for a rule.

  Each rule can optionally include up to one of each of the following
  conditions: http-request-method, host-header, path-pattern, and source-ip.
  Each rule can also optionally include one or more of each of the following
  conditions: http-header and query-string. Note that the value for a condition
  can't be empty.

  For more information, see Quotas for your Application Load Balancers.
  """
  @type rule_condition ::
          [
            field: binary,
            values: [binary, ...],
            host_header_config: host_header_config()
          ]
          | %{
              optional(:field) => binary,
              optional(:values) => [binary, ...],
              optional(:host_header_config) => host_header_config()
            }

  @typedoc """
  A list of `t:rule_condition/0`
  """
  @type conditions() :: [rule_condition, ...]

  @typedoc """
  Optional parameters for `modify_rule/2`.
  """
  @type modify_rule_opts ::
          [
            actions: actions(),
            conditions: conditions()
          ]
          | %{
              optional(:actions) => actions(),
              optional(:conditions) => conditions()
            }

  @typedoc """
  Optional parameters for `describe_rules/1`.
  """
  @type describe_rules_opts ::
          [
            listener_arn: listener_arn(),
            rule_arns: [rule_arn(), ...],
            marker: marker(),
            page_size: integer
          ]
          | %{
              optional(:listener_arn) => listener_arn(),
              optional(:rule_arns) => [rule_arn(), ...],
              optional(:marker) => marker(),
              optional(:page_size) => integer
            }

  @typedoc """
  Optional parameters for `describe_account_limits/1`.
  """
  @type describe_account_limits_opts ::
          [
            marker: marker(),
            # Minimum value of 1. Maximum value of 400
            page_size: page_size()
          ]
          | %{
              optional(:marker) => marker(),
              optional(:page_size) => page_size()
            }

  @typedoc """
  Optional parameters for `modify_target_group/2`.
  """
  @type modify_target_group_opts ::
          [
            health_check_enabled: health_check_enabled(),
            health_check_interval_seconds: health_check_interval_seconds(),
            health_check_path: health_check_path(),
            health_check_port: health_check_port(),
            health_check_protocol: health_check_protocol(),
            health_check_timeout_seconds: health_check_timeout_seconds(),
            healthy_threshold_count: healthy_threshold_count(),
            matcher: matcher(),
            unhealthy_threshold_count: unhealthy_threshold_count()
          ]
          | %{
              optional(:health_check_enabled) => health_check_enabled(),
              optional(:health_check_interval_seconds) => health_check_interval_seconds(),
              optional(:health_check_path) => health_check_path(),
              optional(:health_check_port) => health_check_port(),
              optional(:health_check_protocol) => health_check_protocol(),
              optional(:health_check_timeout_seconds) => health_check_timeout_seconds(),
              optional(:healthy_threshold_count) => healthy_threshold_count(),
              optional(:matcher) => matcher(),
              optional(:unhealthy_threshold_count) => unhealthy_threshold_count()
            }

  @typedoc """
  Optional parameters for `describe_listeners/1`.
  """
  @type describe_listeners_opts ::
          [
            listener_arns: [listener_arn(), ...],
            load_balancer_arn: load_balancer_arn(),
            marker: marker(),
            page_size: page_size()
          ]
          | %{
              optional(:listener_arns) => [listener_arn(), ...],
              optional(:load_balancer_arn) => load_balancer_arn(),
              optional(:marker) => marker(),
              optional(:page_size) => page_size()
            }

  @typedoc """
  Optional parameters for `set_security_groups/3`.
  """
  @type set_security_groups_opts ::
          [
            enforce_security_group_inbound_rules_on_private_link_traffic: binary
          ]
          | %{
              optional(:enforce_security_group_inbound_rules_on_private_link_traffic) => binary
            }

  @typedoc """
  Optional parameters for `describe_listener_certificates/2`.
  """
  @type describe_listener_certificates_opts ::
          [
            marker: marker(),
            page_size: page_size()
          ]
          | %{
              optional(:marker) => marker(),
              optional(:page_size) => page_size()
            }

  @typedoc """
  The type of transform.

  - "host-header-rewrite" - Rewrite the host header.
  - "url-rewrite" - Rewrite the request URL.

  Valid Values
  ```
  "host-header-rewrite" | "url-rewrite"
  ```
  """
  @type rule_transform_type() :: binary

  @typedoc """
  The regular expression to match in the input string

  The maximum length of the string is 1,024 characters.
  """
  @type regex() :: binary()

  @typedoc """
  The replacement string to use when rewriting the matched input

  The maximum length of the string is 1,024 characters.
  You can specify capture groups in the regular expression (for example, $1 and $2).
  """
  @type replace() :: binary()

  @typedoc """
  Information about a rewrite transform to match a pattern and replace it with the specified string.
  """
  @type rewrite_config() :: [
          {:regex, regex()},
          {:replace, replace()}
        ]

  @typedoc """
  Information about a host header rewrite transform

  This transform matches a pattern in the host header in an HTTP request and replaces it
  with the specified string.
  """
  @type host_header_rewrite_config() :: [
          {:rewrites, [rewrite_config()]}
        ]

  @type url_rewrite_config() :: [
          {:rewrites, [rewrite_config()]}
        ]

  @typedoc """
  Information about a transform to apply to requests that match a rule

  Transforms are applied to requests before they are sent to targets.
  """
  @type rule_transform :: [
          {:type, rule_transform_type()},
          {:host_header_rewrite_config, host_header_rewrite_config()},
          {:url_rewrite_config, url_rewrite_config()}
        ]

  @typedoc """
  Optional parameters for `create_rule/5`.
  """
  @type create_rule_opts ::
          [
            {:transforms, [rule_transform()]},
            {:tags, tags()}
          ]
          | %{
              optional(:transforms) => rule_transform(),
              optional(:tags) => tags()
            }

  @typedoc """
  Optional parameters for `describe_load_balancers/1`.
  """
  @type describe_load_balancers_opts ::
          [
            load_balancer_arns: [load_balancer_arn()],
            names: [binary, ...],
            marker: marker(),
            page_size: page_size()
          ]
          | %{
              optional(:load_balancer_arns) => [load_balancer_arn()],
              optional(:names) => [binary, ...],
              optional(:marker) => marker(),
              optional(:page_size) => page_size()
            }

  @typedoc """
  Optional parameters for `describe_ssl_policies/1`.
  """
  @type describe_ssl_policies_opts ::
          [
            ssl_policy_names: [binary, ...],
            marker: marker(),
            page_size: integer
          ]
          | %{
              optional(:ssl_policy_names) => [binary, ...],
              optional(:marker) => marker(),
              optional(:page_size) => page_size()
            }

  @typedoc """
  Optional parameters for `describe_target_groups/1`.
  """
  @type describe_target_groups_opts ::
          [
            load_balancer_arn: load_balancer_arn(),
            target_group_arns: [target_group_arn()],
            names: [binary, ...],
            marker: marker(),
            page_size: page_size()
          ]
          | %{
              optional(:load_balancer_arn) => load_balancer_arn(),
              optional(:target_group_arns) => [target_group_arn()],
              optional(:names) => [binary, ...],
              optional(:marker) => marker(),
              optional(:page_size) => page_size()
            }

  @typedoc """
  Optional parameters for `describe_target_health/2`.
  """
  @type describe_target_health_opts ::
          [targets: target_descriptions]
          | %{
              optional(:targets) => target_descriptions()
            }

  @typedoc """
  Optional parameters for `set_subnets/3`.
  """
  @type set_subnets_opts ::
          [
            enable_prefix_for_ipv6_source_nat: enable_prefix_for_ipv6_source_nat(),
            ip_address_type: ip_address_type(),
            subnet_mappings: [subnet_mapping(), ...],
            subnets: subnets()
          ]
          | %{
              optional(:enable_prefix_for_ipv6_source_nat) => enable_prefix_for_ipv6_source_nat(),
              optional(:ip_address_type) => ip_address_type(),
              optional(:subnet_mappings) => [subnet_mapping(), ...],
              optional(:subnets) => subnets()
            }

  @doc """
  Adds the specified SSL server certificate to the certificate list for the specified HTTPS or TLS listener.

  If the certificate in already in the certificate list, the call is successful but the certificate is not added again.

  To list the certificates for your listener, use `describe_listener_certificates/1`.
  To remove certificates from your listener, use `remove_listener_certificates/3`.

  ## Examples:

      iex> certificates = [
      ...>   %{certificate_arn: "certificate1_arn", is_default: true},
      ...>   %{certificate_arn: "certificate2_arn"}
      ...> ]
      [
        %{certificate_arn: "certificate1_arn", is_default: true},
        %{certificate_arn: "certificate2_arn"}
      ]
      iex> ExAws.ElasticLoadBalancingV2.add_listener_certificates("listener_arn", certificates)
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "AddListenerCertificates",
          "Certificates.member.1.CertificateArn" => "certificate1_arn",
          "Certificates.member.1.IsDefault" => true,
          "Certificates.member.2.CertificateArn" => "certificate2_arn",
          "ListenerArn" => "listener_arn",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :add_listener_certificates,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec add_listener_certificates(listener_arn(), certificates()) :: ExAws.Operation.Query.t()
  def add_listener_certificates(listener_arn, certificates) do
    [{:listener_arn, listener_arn}, {:certificates, certificates}]
    |> build_request(:add_listener_certificates)
  end

  @doc """
  Adds the specified tags to the specified Elastic Load Balancing resource.

  You can tag your Application Load Balancers, Network Load Balancers, and your target groups.

  Each tag consists of a key and an optional value. If a resource already has a tag with the same
  key, `add_tags/1` updates its value.

  To list the current tags for your resources, use `describe_tags/1`. To remove tags from
  your resources, use `remove_tags/1`.

  ## Examples:

      iex> tags = [%{key: "hello", value: "test"}, %{key: "foo", value: "bar"}]
      iex> ExAws.ElasticLoadBalancingV2.add_tags(["resource_arn1", "resource_arn2"], tags)
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "AddTags",
          "ResourceArns.member.1" => "resource_arn1",
          "ResourceArns.member.2" => "resource_arn2",
          "Tags.member.1.Key" => "hello",
          "Tags.member.1.Value" => "test",
          "Tags.member.2.Key" => "foo",
          "Tags.member.2.Value" => "bar",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :add_tags,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }

      iex> tags = [hello: "test", foo: "bar"]
      iex> ExAws.ElasticLoadBalancingV2.add_tags(["resource_arn1", "resource_arn2"], tags)
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "AddTags",
          "ResourceArns.member.1" => "resource_arn1",
          "ResourceArns.member.2" => "resource_arn2",
          "Tags.member.1.Key" => "hello",
          "Tags.member.1.Value" => "test",
          "Tags.member.2.Key" => "foo",
          "Tags.member.2.Value" => "bar",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :add_tags,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec add_tags(resource_arns(), tags()) :: ExAws.Operation.Query.t()
  def add_tags(resource_arns, tags) do
    [{:resource_arns, resource_arns}, {:tags, tags}]
    |> build_request(:add_tags)
  end

  @doc """
  Adds the specified revocation file to the specified trust store.

  ## Examples:

      iex> opts = [revocation_contents: [%{revocation_type: "CRL"}]]
      iex> trust_store_arn = "trust_store_arn"
      iex> ExAws.ElasticLoadBalancingV2.add_trust_store_revocations(trust_store_arn, opts)
      %ExAws.Operation.Query{
              action: :add_trust_store_revocations,
              content_encoding: "identity",
              params: %{"Action" => "AddTrustStoreRevocations", "TrustStoreArn" => "trust_store_arn", "Version" => "2015-12-01", "RevocationContents.member.1.RevocationType" => "CRL"},
              parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2,
              path: "/",
              service: :elasticloadbalancing
            }
  """
  @spec add_trust_store_revocations(trust_store_arn(), add_trust_store_revocations_opts()) :: ExAws.Operation.Query.t()
  def add_trust_store_revocations(trust_store_arn, opts \\ []) do
    opts
    |> keyword_to_map()
    |> Map.merge(%{trust_store_arn: trust_store_arn})
    |> build_request(:add_trust_store_revocations)
  end

  @doc """
  Creates a listener for the specified Application Load Balancer
  or Network Load Balancer.

  You can create up to 10 listeners per load balancer.

  To update a listener, use `modify_listener/1`. When you are finished with a
  listener, you can delete it using `delete_listener/1`. If you are finished
  with both the listener and the load balancer, you can delete them both
  using `delete_load_balancer/1`.

  More information:
  * [Listeners for Your Application Load Balancers](http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html)
  in the *Application Load Balancers Guide*
  * [Listeners for Your Network Load Balancers](http://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-listeners.html)
  in the *Network Load Balancers Guide*
  * This function replaces the deprecated `create_listener/5` function and moves all optional parameters to the opts argument.

  ## Examples:

      iex> default_actions = [%{type: "forward", target_group_arn: "target_arn"}]
      iex> load_balancer_arn = "load_balancer_arn"
      iex> opts = [protocol: "HTTP", port: 80]
      iex> ExAws.ElasticLoadBalancingV2.create_listener(load_balancer_arn, default_actions, opts)
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "CreateListener",
          "DefaultActions.member.1.TargetGroupArn" => "target_arn",
          "DefaultActions.member.1.Type" => "forward",
          "LoadBalancerArn" => "load_balancer_arn",
          "Port" => 80,
          "Protocol" => "HTTP",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :create_listener,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
      iex> opts = %{protocol: "HTTP", port: 80}
      iex> ExAws.ElasticLoadBalancingV2.create_listener(load_balancer_arn, default_actions, opts)
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "CreateListener",
          "DefaultActions.member.1.TargetGroupArn" => "target_arn",
          "DefaultActions.member.1.Type" => "forward",
          "LoadBalancerArn" => "load_balancer_arn",
          "Port" => 80,
          "Protocol" => "HTTP",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :create_listener,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec create_listener(load_balancer_arn(), [action, ...], create_listener_opts()) :: ExAws.Operation.Query.t()
  def create_listener(load_balancer_arn, default_actions, opts \\ []) do
    opts
    |> keyword_to_map()
    |> Map.merge(%{
      load_balancer_arn: load_balancer_arn,
      default_actions: default_actions
    })
    |> build_request(:create_listener)
  end

  @doc """
  Creates a listener for the specified Application Load Balancer

  ## Examples:

      iex> default_actions = [%{type: "forward", target_group_arn: "target_arn"}]
      iex> protocol = "HTTP"
      iex> port = 80
      iex> ExAws.ElasticLoadBalancingV2.create_listener("load_balancer_arn", protocol, port, default_actions)
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "CreateListener",
          "DefaultActions.member.1.TargetGroupArn" => "target_arn",
          "DefaultActions.member.1.Type" => "forward",
          "LoadBalancerArn" => "load_balancer_arn",
          "Port" => 80,
          "Protocol" => "HTTP",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :create_listener,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @deprecated "Use `create_listener/3` instead"
  @spec create_listener(
          load_balancer_arn(),
          protocol(),
          port_num(),
          [action, ...],
          deprecated_create_listener_opts()
        ) :: ExAws.Operation.Query.t()
  def create_listener(load_balancer_arn, protocol, port_num, default_actions, opts \\ []) do
    opts
    |> keyword_to_map()
    |> Map.merge(%{
      load_balancer_arn: load_balancer_arn,
      protocol: protocol,
      port: port_num,
      default_actions: default_actions
    })
    |> build_request(:create_listener)
  end

  @doc """
  Creates an Application Load Balancer or a Network Load Balancer.

  When you create a load balancer, you can specify security groups, subnets,
  IP address type, and tags. Otherwise, you could do so later using `set_security_groups/3`,
  `set_subnets/3`, `set_ip_address_type/3`, and `add_tags/2`.

  To create listeners for your load balancer, use `create_listener/3`. To describe your
  current load balancers, see `describe_load_balancers/1`. When you are finished with a
  load balancer, you can delete it using `delete_load_balancer/1`.

  You can create up to 20 load balancers per region per account. You can request an
  increase for the number of load balancers for your account.

  More information:
  * [Limits for Your Application Load Balancer](http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-limits.html)
  in the *Application Load Balancers Guide*
  * [Limits for Your Network Load Balancer](http://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-limits.html)
  in the *Network Load Balancers Guide*

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.create_load_balancer("Loader")
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "CreateLoadBalancer",
          "Name" => "Loader",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :create_load_balancer,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }

      iex> opts = [
      ...> schema: "internet-facing",
      ...> subnet_mappings: [
      ...>   %{subnet_id: "1.2.3.4", allocation_id: "i2234342"}
      ...> ],
      ...> subnets: ["1.2.3.4", "5.6.7.8"],
      ...> security_groups: ["Secure123", "Secure456"],
      ...> type: "application", ip_address_type: "ipv4"]
      iex> ExAws.ElasticLoadBalancingV2.create_load_balancer("Loader", opts)
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "CreateLoadBalancer",
          "IpAddressType" => "ipv4",
          "Name" => "Loader",
          "Schema" => "internet-facing",
          "SecurityGroups.member.1" => "Secure123",
          "SecurityGroups.member.2" => "Secure456",
          "SubnetMappings.member.1.AllocationId" => "i2234342",
          "SubnetMappings.member.1.SubnetId" => "1.2.3.4",
          "Subnets.member.1" => "1.2.3.4",
          "Subnets.member.2" => "5.6.7.8",
          "Type" => "application",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :create_load_balancer,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec create_load_balancer(load_balancer_name, create_load_balancer_opts) :: ExAws.Operation.Query.t()
  def create_load_balancer(load_balancer_name, opts \\ []) do
    opts
    |> keyword_to_map()
    |> Map.merge(%{name: load_balancer_name})
    |> build_request(:create_load_balancer)
  end

  @doc """
  Creates a rule for the specified listener.

  The listener must be associated with an Application Load Balancer. Rules are
  evaluated in priority order, from the lowest value to the highest value. When
  the condition for a rule is met, the specified action is taken. If no conditions
  are met, the action for the default rule is taken.

  More information:
  * [Listener Rules](http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html#listener-rules)
  *Application Load Balancers Guide*

  To view your current rules, use `describe_rules/1`. To update a rule, use
  `modify_rule/1`. To set the priorities of your rules, use `set_rule_priorities/1`.
  To delete a rule, use `delete_rule/1`.

  ## Examples

      iex> conditions = [%{field: "path-pattern", values: ["/images/*"]}]
      iex> actions = [%{type: "forward", target_group_arn: "target_arn"}]
      iex> priority = 10
      iex> listener_arn = "arn:aws:test_arn"
      iex> ExAws.ElasticLoadBalancingV2.create_rule(listener_arn, conditions, priority, actions)
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "CreateRule",
          "Actions.member.1.TargetGroupArn" => "target_arn",
          "Actions.member.1.Type" => "forward",
          "Conditions.member.1.Field" => "path-pattern",
          "Conditions.member.1.Values.1" => "/images/*",
          "ListenerArn" => "arn:aws:test_arn",
          "Priority" => 10,
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :create_rule,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec create_rule(listener_arn(), conditions(), priority(), actions(), create_rule_opts()) ::
          ExAws.Operation.Query.t()
  def create_rule(listener_arn, conditions, priority, actions, opts \\ []) do
    opts
    |> keyword_to_map()
    |> Map.merge(%{
      listener_arn: listener_arn,
      conditions: conditions,
      priority: priority,
      actions: actions
    })
    |> build_request(:create_rule)
  end

  @doc """
  Creates a target group.

  To register targets with the target group, use `register_targets/3`. To
  update the health check settings for the target group, use
  `modify_target_group/1`. To monitor the health of targets in the target group,
  use `describe_target_health/1`. To route traffic to the targets in a target group,
  specify the target group in an action using `create_listener/3` or `create_rule/5`.
  To delete a target group, use `delete_target_group/2`.

  More information:
  * [Target Groups for Your Application Load Balancers](http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html)
  in the *Application Load Balancers Guide*
  * [Target Groups for Your Network Load Balancers](http://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-target-groups.html)
  in the *Network Load Balancers Guide*.

  ## Examples:

      iex> opts = [protocol: "HTTP", port: 80, health_check_path: "/health", vpc_id: "vpc_id"]
      iex> ExAws.ElasticLoadBalancingV2.create_target_group("target_group_name", opts)
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "CreateTargetGroup",
          "HealthCheckPath" => "/health",
          "Name" => "target_group_name",
          "Port" => 80,
          "Protocol" => "HTTP",
          "Version" => "2015-12-01",
          "VpcId" => "vpc_id"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :create_target_group,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
      iex> # Demonstrate passing opts as a map
      iex> opts = %{protocol: "HTTP", port: 80, health_check_path: "/health", vpc_id: "vpc_id"}
      iex> ExAws.ElasticLoadBalancingV2.create_target_group("target_group_name", opts)
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "CreateTargetGroup",
          "HealthCheckPath" => "/health",
          "Name" => "target_group_name",
          "Port" => 80,
          "Protocol" => "HTTP",
          "Version" => "2015-12-01",
          "VpcId" => "vpc_id"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :create_target_group,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec create_target_group(target_group_name(), create_target_group_opts()) :: ExAws.Operation.Query.t()
  def create_target_group(name, opts \\ []) do
    opts
    |> keyword_to_map()
    |> Map.merge(%{name: name})
    |> build_request(:create_target_group)
  end

  @doc """
  Creates a trust store.

  For more information, see Mutual TLS for Application Load Balancers.

  ## Examples:

      iex> trust_store_name = "my-trust-store"
      iex> ca_certificates_bundle_s3_bucket = "amzn-s3-demo-bucket"
      iex> ca_certificates_bundle_s3_key = "CACertBundle.pem"
      iex> ExAws.ElasticLoadBalancingV2.create_trust_store(trust_store_name, ca_certificates_bundle_s3_bucket, ca_certificates_bundle_s3_key)
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "CreateTrustStore",
          "CaCertificatesBundleS3Bucket" => "amzn-s3-demo-bucket",
          "CaCertificatesBundleS3Key" => "CACertBundle.pem",
          "TrustStoreName" => "my-trust-store",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :create_trust_store,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec create_trust_store(
          trust_store_name(),
          ca_certificates_bundle_s3_bucket(),
          ca_certificates_bundle_s3_key(),
          create_trust_store_opts()
        ) :: ExAws.Operation.Query.t()
  def create_trust_store(trust_store_name, ca_certificates_bundle_s3_bucket, ca_certificates_bundle_s3_key, opts \\ []) do
    opts
    |> keyword_to_map()
    |> Map.merge(%{
      trust_store_name: trust_store_name,
      ca_certificates_bundle_s3_bucket: ca_certificates_bundle_s3_bucket,
      ca_certificates_bundle_s3_key: ca_certificates_bundle_s3_key
    })
    |> build_request(:create_trust_store)
  end

  @doc """
  Deletes the specified listener.

  Alternatively, your listener is deleted when you delete the load balancer
  it is attached to using `delete_load_balancer/1`.

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.delete_listener("listener_arn")
        %ExAws.Operation.Query{
          path: "/",
          params: %{
            "Action" => "DeleteListener",
            "ListenerArn" => "listener_arn",
            "Version" => "2015-12-01"
          },
          content_encoding: "identity",
          service: :elasticloadbalancing,
          action: :delete_listener,
          parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
        }
  """
  @spec delete_listener(listener_arn()) :: ExAws.Operation.Query.t()
  def delete_listener(listener_arn) do
    [{:listener_arn, listener_arn}]
    |> build_request(:delete_listener)
  end

  @doc """
  Deletes the specified Application Load Balancer or Network Load Balancer
  and its attached listeners.

  You can't delete a load balancer if deletion protection is enabled.
  If the load balancer does not exist or has already been deleted,
  the call succeeds.

  Deleting a load balancer does not affect its registered targets. For
  example, your EC2 instances continue to run and are still registered
  to their target groups. If you no longer need these EC2 instances,
  you can stop or terminate them.

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.delete_load_balancer("load_balancer_arn")
        %ExAws.Operation.Query{
          path: "/",
          params: %{
            "Action" => "DeleteLoadBalancer",
            "LoadBalancerArn" => "load_balancer_arn",
            "Version" => "2015-12-01"
          },
          content_encoding: "identity",
          service: :elasticloadbalancing,
          action: :delete_load_balancer,
          parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
        }
  """
  @spec delete_load_balancer(load_balancer_arn()) :: ExAws.Operation.Query.t()
  def delete_load_balancer(load_balancer_arn) do
    [{:load_balancer_arn, load_balancer_arn}]
    |> build_request(:delete_load_balancer)
  end

  @doc """
  Deletes the specified rule.

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.delete_rule("rule_arn")
        %ExAws.Operation.Query{
          path: "/",
          params: %{
            "Action" => "DeleteRule",
            "RuleArn" => "rule_arn",
            "Version" => "2015-12-01"
          },
          content_encoding: "identity",
          service: :elasticloadbalancing,
          action: :delete_rule,
          parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
        }
  """
  @spec delete_rule(rule_arn()) :: ExAws.Operation.Query.t()
  def delete_rule(rule_arn) do
    [{:rule_arn, rule_arn}]
    |> build_request(:delete_rule)
  end

  @doc """
  Deletes the specified target group.

  You can delete a target group if it is not referenced by any
  actions. Deleting a target group also deletes any associated
  health checks.

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.delete_target_group("target_group_arn")
        %ExAws.Operation.Query{
          path: "/",
          params: %{
            "Action" => "DeleteTargetGroup",
            "TargetGroupArn" => "target_group_arn",
            "Version" => "2015-12-01"
          },
          content_encoding: "identity",
          service: :elasticloadbalancing,
          action: :delete_target_group,
          parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
        }
  """
  @spec delete_target_group(target_group_arn()) :: ExAws.Operation.Query.t()
  def delete_target_group(target_group_arn) do
    [{:target_group_arn, target_group_arn}]
    |> build_request(:delete_target_group)
  end

  @doc """
  Deletes the specified trust store.

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.delete_trust_store("trust_store_arn")
        %ExAws.Operation.Query{
          path: "/",
          params: %{
            "Action" => "DeleteTrustStore",
            "TrustStoreArn" => "trust_store_arn",
            "Version" => "2015-12-01"
          },
          content_encoding: "identity",
          service: :elasticloadbalancing,
          action: :delete_trust_store,
          parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
        }
  """
  def delete_trust_store(trust_store_arn) do
    [{:trust_store_arn, trust_store_arn}]
    |> build_request(:delete_trust_store)
  end

  @doc """
  Deregisters the specified targets from the specified target group.

  After the targets are deregistered, they no longer receive traffic
  from the load balancer.

  ## Examples:

        iex>  targets = [%{id: "test"}, %{id: "test2", port: 8088, availability_zone: "us-east-1"}]
        [%{id: "test"}, %{id: "test2", port: 8088, availability_zone: "us-east-1"}]
        iex> ExAws.ElasticLoadBalancingV2.deregister_targets("target_group_arn", targets)
        %ExAws.Operation.Query{
          path: "/",
          params: %{
            "Action" => "DeregisterTargets",
            "TargetGroupArn" => "target_group_arn",
            "Targets.member.1.Id" => "test",
            "Targets.member.2.AvailabilityZone" => "us-east-1",
            "Targets.member.2.Id" => "test2",
            "Targets.member.2.Port" => 8088,
            "Version" => "2015-12-01"
          },
          content_encoding: "identity",
          service: :elasticloadbalancing,
          action: :deregister_targets,
          parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
        }

        iex> ExAws.ElasticLoadBalancingV2.deregister_targets("target_group_arn", [%{id: "i-0f76fade435676abd"}])
        %ExAws.Operation.Query{
          path: "/",
          params: %{
            "Action" => "DeregisterTargets",
            "TargetGroupArn" => "target_group_arn",
            "Targets.member.1.Id" => "i-0f76fade435676abd",
            "Version" => "2015-12-01"
          },
          content_encoding: "identity",
          service: :elasticloadbalancing,
          action: :deregister_targets,
          parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
        }
  """
  @spec deregister_targets(target_group_arn(), target_descriptions()) :: ExAws.Operation.Query.t()
  def deregister_targets(target_group_arn, targets) do
    [{:target_group_arn, target_group_arn}, {:targets, targets}]
    |> build_request(:deregister_targets)
  end

  @doc """
  Describes the current Elastic Load Balancing resource limits
  for your AWS account.

  More information:
  * [Limits for Your Application Load Balancers](http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-limits.html)
  in the *Application Load Balancer Guide*
  * [Limits for Your Network Load Balancers](http://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-limits.html)
  in the *Network Load Balancers Guide*.

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.describe_account_limits()
        %ExAws.Operation.Query{
          path: "/",
          params: %{"Action" => "DescribeAccountLimits", "Version" => "2015-12-01"},
          content_encoding: "identity",
          service: :elasticloadbalancing,
          action: :describe_account_limits,
          parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
        }
  """
  @spec describe_account_limits(describe_account_limits_opts()) :: ExAws.Operation.Query.t()
  def describe_account_limits(opts \\ []) do
    opts |> build_request(:describe_account_limits)
  end

  @doc """
  Describes the capacity reservation status for the specified load balancer.

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.describe_capacity_reservation("load_balancer_arn")
        %ExAws.Operation.Query{
          path: "/",
          params: %{
            "Action" => "DescribeCapacityReservation",
            "LoadBalancerArn" => "load_balancer_arn",
            "Version" => "2015-12-01"
          },
          content_encoding: "identity",
          service: :elasticloadbalancing,
          action: :describe_capacity_reservation,
          parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
        }
  """
  def describe_capacity_reservation(load_balancer_arn) do
    [{:load_balancer_arn, load_balancer_arn}]
    |> build_request(:describe_capacity_reservation)
  end

  @doc """
  Describes the attributes for the specified listener

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.describe_listener_attributes("listener_arn")
        %ExAws.Operation.Query{
          path: "/",
          params: %{
            "Action" => "DescribeListenerAttributes",
            "ListenerArn" => "listener_arn",
            "Version" => "2015-12-01"
          },
          content_encoding: "identity",
          service: :elasticloadbalancing,
          action: :describe_listener_attributes,
          parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
        }
  """
  def describe_listener_attributes(listener_arn) do
    [{:listener_arn, listener_arn}]
    |> build_request(:describe_listener_attributes)
  end

  @doc """
  Describes the certificates for the specified secure listener.

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.describe_listener_certificates("listener_arn")
        %ExAws.Operation.Query{
          path: "/",
          params: %{
            "Action" => "DescribeListenerCertificates",
            "ListenerArn" => "listener_arn",
            "Version" => "2015-12-01"
          },
          content_encoding: "identity",
          service: :elasticloadbalancing,
          action: :describe_listener_certificates,
          parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
        }
  """
  @spec describe_listener_certificates(listener_arn(), describe_listener_certificates_opts()) ::
          ExAws.Operation.Query.t()
  def describe_listener_certificates(listener_arn, opts \\ []) do
    opts
    |> keyword_to_map()
    |> Map.merge(%{
      listener_arn: listener_arn
    })
    |> build_request(:describe_listener_certificates)
  end

  @doc """
  Describes the specified listeners or the listeners for the
  specified Application Load Balancer or Network Load Balancer.

  You must specify either a load balancer or one or more listeners.

  ## Example

      iex> ExAws.ElasticLoadBalancingV2.describe_listeners()
      %ExAws.Operation.Query{
        path: "/",
        params: %{"Action" => "DescribeListeners", "Version" => "2015-12-01"},
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :describe_listeners,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec describe_listeners(describe_listeners_opts()) :: ExAws.Operation.Query.t()
  def describe_listeners(opts \\ []) do
    opts |> build_request(:describe_listeners)
  end

  @doc """
  Describes the attributes for the specified Application Load
  Balancer or Network Load Balancer.

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.describe_load_balancer_attributes("load_balancer_arn")
        %ExAws.Operation.Query{
          path: "/",
          params: %{
            "Action" => "DescribeLoadBalancerAttributes",
            "LoadBalancerArn" => "load_balancer_arn",
            "Version" => "2015-12-01"
          },
          content_encoding: "identity",
          service: :elasticloadbalancing,
          action: :describe_load_balancer_attributes,
          parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
        }
  """
  @spec describe_load_balancer_attributes(load_balancer_arn()) :: ExAws.Operation.Query.t()
  def describe_load_balancer_attributes(load_balancer_arn) do
    [{:load_balancer_arn, load_balancer_arn}]
    |> build_request(:describe_load_balancer_attributes)
  end

  @doc """
  Describes the specified load balancers or all of your
  load balancers.

  To describe the listeners for a load balancer, use `describe_listeners/1`.
  To describe the attributes for a load balancer, use `describe_load_balancer_attributes/1`.

  The options that can be passed into `describe_load_balancers/1` allow load_balancer_arns or names
  (there would not be a reason ordinarily to specify both). Elastic Load Balancing provides
  two versions of ARNS (one for Classic and one for Application Load Balancer). The syntax for
  each is below:

  Classic Load Balancer ARN Syntax:

      arn:aws:elasticloadbalancing:region:account-id:loadbalancer/name

  Application Load Balancer ARN Syntax:

      arn:aws:elasticloadbalancing:region:account-id:loadbalancer/app/load-balancer-name/load-balancer-id
      arn:aws:elasticloadbalancing:region:account-id:listener/app/load-balancer-name/load-balancer-id/listener-id
      arn:aws:elasticloadbalancing:region:account-id:listener-rule/app/load-balancer-name/load-balancer-id/listener-id/rule-id
      arn:aws:elasticloadbalancing:region:account-id:targetgroup/target-group-name/target-group-id

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.describe_load_balancers()
      %ExAws.Operation.Query{
        path: "/",
        params: %{"Action" => "DescribeLoadBalancers", "Version" => "2015-12-01"},
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :describe_load_balancers,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec describe_load_balancers(describe_load_balancers_opts()) :: ExAws.Operation.Query.t()
  def describe_load_balancers(opts \\ []) do
    opts |> build_request(:describe_load_balancers)
  end

  @doc """
  Describes the specified rules or the rules for the specified listener.

  You must specify either a listener or one or more rules.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.describe_rules()
      %ExAws.Operation.Query{
        path: "/",
        params: %{"Action" => "DescribeRules", "Version" => "2015-12-01"},
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :describe_rules,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }

      iex> ExAws.ElasticLoadBalancingV2.describe_rules([listener_arn: "listener_arn", rule_arns: ["rule_arns"]])
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "DescribeRules",
          "ListenerArn" => "listener_arn",
          "RuleArns.member.1" => "rule_arns",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :describe_rules,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec describe_rules(describe_rules_opts) :: ExAws.Operation.Query.t()
  def describe_rules(opts \\ []) do
    opts |> build_request(:describe_rules)
  end

  @doc """
  Describes the specified policies or all policies used for SSL negotiation.

  More information:
  * [Security Policies](http://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#describe-ssl-policies)
  in the *Application Load Balancers Guide*.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.describe_ssl_policies()
      %ExAws.Operation.Query{
        path: "/",
        params: %{"Action" => "DescribeSslPolicies", "Version" => "2015-12-01"},
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :describe_ssl_policies,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }

      iex> ExAws.ElasticLoadBalancingV2.describe_ssl_policies([ssl_policy_names: ["policy1", "policy2"]])
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "DescribeSslPolicies",
          "SslPolicyNames.1" => "policy1",
          "SslPolicyNames.2" => "policy2",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :describe_ssl_policies,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec describe_ssl_policies(describe_ssl_policies_opts()) :: ExAws.Operation.Query.t()
  def describe_ssl_policies(opts \\ []) do
    opts |> build_request(:describe_ssl_policies)
  end

  @doc """
  Describes the tags for the specified resources.

  You can describe the tags for one or more Application Load Balancers,
  Network Load Balancers, and target groups.  You can specify up to 20
  resources in a single call.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.describe_tags(["resource_arn1", "resource_arn2"])
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "DescribeTags",
          "ResourceArns.member.1" => "resource_arn1",
          "ResourceArns.member.2" => "resource_arn2",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :describe_tags,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec describe_tags(resource_arns()) :: ExAws.Operation.Query.t()
  def describe_tags(resource_arns) do
    [{:resource_arns, resource_arns}]
    |> build_request(:describe_tags)
  end

  @doc """
  Describes the attributes for the specified target group.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.describe_target_group_attributes(["target_group_arn1", "target_group_arn2"])
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "DescribeTargetGroupAttributes",
          "TargetGroupArn.1" => "target_group_arn1",
          "TargetGroupArn.2" => "target_group_arn2",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :describe_target_group_attributes,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec describe_target_group_attributes(target_group_arn()) :: ExAws.Operation.Query.t()
  def describe_target_group_attributes(target_group_arn) do
    [{:target_group_arn, target_group_arn}]
    |> build_request(:describe_target_group_attributes)
  end

  @doc """
   Describes the specified target groups or all of your target groups.

   By default, all target groups are described. Alternatively, you can
   specify one of the following to filter the results: the ARN of the
   load balancer, the names of one or more target groups, or the ARNs
   of one or more target groups. To describe the targets for a
   target group, use `describe_target_health/1`. To describe the attributes
   of a target group, use `describe_target_group_attributes/1`.

   ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.describe_target_groups()
      %ExAws.Operation.Query{
        path: "/",
        params: %{"Action" => "DescribeTargetGroups", "Version" => "2015-12-01"},
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :describe_target_groups,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }

      iex> opts = [load_balancer_arn: "load_balancer_arn", target_group_arns: ["target_group_arn1", "target_group_arn2"]]
      [
        load_balancer_arn: "load_balancer_arn",
        target_group_arns: ["target_group_arn1", "target_group_arn2"]
      ]
      iex> ExAws.ElasticLoadBalancingV2.describe_target_groups(opts)
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "DescribeTargetGroups",
          "LoadBalancerArn" => "load_balancer_arn",
          "TargetGroupArns.member.1" => "target_group_arn1",
          "TargetGroupArns.member.2" => "target_group_arn2",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :describe_target_groups,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
      iex> opts = %{load_balancer_arn: "load_balancer_arn", target_group_arns: ["target_group_arn1", "target_group_arn2"]}
      iex> ExAws.ElasticLoadBalancingV2.describe_target_groups(opts)
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "DescribeTargetGroups",
          "LoadBalancerArn" => "load_balancer_arn",
          "TargetGroupArns.member.1" => "target_group_arn1",
          "TargetGroupArns.member.2" => "target_group_arn2",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :describe_target_groups,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec describe_target_groups(describe_target_groups_opts()) :: ExAws.Operation.Query.t()
  def describe_target_groups(opts \\ []) do
    opts |> build_request(:describe_target_groups)
  end

  @doc """
  Describes the health of the specified targets or all of your targets.
  """
  @spec describe_target_health(target_group_arn(), describe_target_health_opts()) :: ExAws.Operation.Query.t()
  def describe_target_health(target_group_arn, opts \\ []) do
    [{:target_group_arn, target_group_arn} | opts]
    |> build_request(:describe_target_health)
  end

  @doc """
  Describes all resources associated with the specified trust store

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.describe_trust_store_associations("trust_store_arn")
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "DescribeTrustStoreAssociations",
          "TrustStoreArn" => "trust_store_arn",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :describe_trust_store_associations,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec describe_trust_store_associations(trust_store_arn(), describe_trust_store_associations_opts()) ::
          ExAws.Operation.Query.t()
  def describe_trust_store_associations(trust_store_arn, opts \\ []) do
    opts
    |> keyword_to_map()
    |> Map.merge(%{trust_store_arn: trust_store_arn})
    |> build_request(:describe_trust_store_associations)
  end

  @doc """
  Describes the revocation files in use by the specified trust store or revocation files

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.describe_trust_store_revocations("trust_store_arn")
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "DescribeTrustStoreRevocations",
          "TrustStoreArn" => "trust_store_arn",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :describe_trust_store_revocations,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
      iex> ExAws.ElasticLoadBalancingV2.describe_trust_store_revocations("trust_store_arn", %{revocation_ids: [3423, 12423]})
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "DescribeTrustStoreRevocations",
          "RevocationIds.member.1" => 3423,
          "RevocationIds.member.2" => 12423,
          "TrustStoreArn" => "trust_store_arn",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :describe_trust_store_revocations,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec describe_trust_store_revocations(trust_store_arn(), describe_trust_store_revocations_opts()) ::
          ExAws.Operation.Query.t()
  def describe_trust_store_revocations(trust_store_arn, opts \\ []) do
    opts
    |> keyword_to_map()
    |> Map.merge(%{trust_store_arn: trust_store_arn})
    |> build_request(:describe_trust_store_revocations)
  end

  @doc """
  Describes all trust stores for the specified account

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.describe_trust_stores()
      %ExAws.Operation.Query{
        path: "/",
        params: %{"Action" => "DescribeTrustStores", "Version" => "2015-12-01"},
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :describe_trust_stores,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
      iex> ExAws.ElasticLoadBalancingV2.describe_trust_stores(%{trust_store_names: ["trust_store1", "trust_store2"]})
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "DescribeTrustStores",
          "TrustStoreNames.1" => "trust_store1",
          "TrustStoreNames.2" => "trust_store2",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :describe_trust_stores,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
      iex> ExAws.ElasticLoadBalancingV2.describe_trust_stores(%{trust_store_arns: ["arn1", "arn2"]})
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "DescribeTrustStores",
          "TrustStoreArns.member.1" => "arn1",
          "TrustStoreArns.member.2" => "arn2",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :describe_trust_stores,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec describe_trust_stores(describe_trust_stores_opts()) :: ExAws.Operation.Query.t()
  def describe_trust_stores(opts \\ []) do
    opts |> build_request(:describe_trust_stores)
  end

  @doc """
  Retrieves the resource policy for a specified resource

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.get_resource_policy("resource_arn")
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "GetResourcePolicy",
          "ResourceArn" => "resource_arn",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :get_resource_policy,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec get_resource_policy(resource_arn()) :: ExAws.Operation.Query.t()
  def get_resource_policy(resource_arn) do
    [{:resource_arn, resource_arn}]
    |> build_request(:get_resource_policy)
  end

  @doc """
  Retrieves the CA certificates bundle for the specified trust store

  This action returns a pre-signed S3 URI which is active for ten minutes.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.get_trust_store_ca_certificates_bundle("trust_store_arn")
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "GetTrustStoreCaCertificatesBundle",
          "TrustStoreArn" => "trust_store_arn",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :get_trust_store_ca_certificates_bundle,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec get_trust_store_ca_certificates_bundle(trust_store_arn()) :: ExAws.Operation.Query.t()
  def get_trust_store_ca_certificates_bundle(trust_store_arn) do
    [{:trust_store_arn, trust_store_arn}]
    |> build_request(:get_trust_store_ca_certificates_bundle)
  end

  @doc """
  Retrieves the specified revocation file.

  This action returns a pre-signed S3 URI which is active for ten minutes.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.get_trust_store_revocation_content("trust_store_arn", 2134342)
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "GetTrustStoreRevocationContent",
          "RevocationId" => 2134342,
          "TrustStoreArn" => "trust_store_arn",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :get_trust_store_revocation_content,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec get_trust_store_revocation_content(trust_store_arn(), revocation_id()) :: ExAws.Operation.Query.t()
  def get_trust_store_revocation_content(trust_store_arn, revocation_id) do
    [{:trust_store_arn, trust_store_arn}, {:revocation_id, revocation_id}]
    |> build_request(:get_trust_store_revocation_content)
  end

  @doc """
  Modifies the specified properties of the specified listener.

  Any properties that you do not specify retain their current values.
  However, changing the protocol from HTTPS to HTTP removes the security
  policy and SSL certificate properties. If you change the protocol from
  HTTP to HTTPS, you must add the security policy and server certificate.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.modify_listener("listener_arn")
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "ModifyListener",
          "ListenerArn" => "listener_arn",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :modify_listener,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }

      iex> opts = [port: 80, protocol: "HTTP", certificates: ["certificate1", "certificate2"]]
      iex> ExAws.ElasticLoadBalancingV2.modify_listener("listener_arn", opts)
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "ModifyListener",
          "Certificates.member.1" => "certificate1",
          "Certificates.member.2" => "certificate2",
          "ListenerArn" => "listener_arn",
          "Port" => 80,
          "Protocol" => "HTTP",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :modify_listener,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec modify_listener(listener_arn(), modify_listener_opts()) :: ExAws.Operation.Query.t()
  def modify_listener(listener_arn, opts \\ []) do
    [{:listener_arn, listener_arn} | opts]
    |> build_request(:modify_listener)
  end

  @doc """
  Modifies the specified attributes of the specified Application Load Balancer
  or Network Load Balancer.

  If any of the specified attributes can't be modified as requested, the call
  fails. Any existing attributes that you do not modify retain their current
  values.
  """
  @spec modify_load_balancer_attributes(load_balancer_arn(), [load_balancer_attribute(), ...]) ::
          ExAws.Operation.Query.t()
  def modify_load_balancer_attributes(load_balancer_arn, attributes) do
    [{:load_balancer_arn, load_balancer_arn}, {:attributes, attributes}]
    |> build_request(:modify_load_balancer_attributes)
  end

  @doc """
  Modifies the specified rule.

  Any existing properties that you do not modify retain their current values.
  To modify the default action, use `modify_listener/1`.
  """
  @spec modify_rule(rule_arn(), modify_rule_opts()) :: ExAws.Operation.Query.t()
  def modify_rule(rule_arn, opts \\ []) do
    [{:rule_arn, rule_arn} | opts] |> build_request(:modify_rule)
  end

  @doc """
  Modifies the health checks used when evaluating the health state of
  the targets in the specified target group.

  To monitor the health of the targets, use `describe_target_health/1`.

  Examples:

      iex> ExAws.ElasticLoadBalancingV2.modify_target_group("target_group_arn")
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "ModifyTargetGroup",
          "TargetGroupArn" => "target_group_arn",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :modify_target_group,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }

      iex> opts = [heath_check_port: 8088, health_check_protocol: "HTTP", health_check_path: "/"]
      [heath_check_port: 8088, health_check_protocol: "HTTP", health_check_path: "/"]
      iex> ExAws.ElasticLoadBalancingV2.modify_target_group("target_group_arn", opts)
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "ModifyTargetGroup",
          "HealthCheckPath" => "/",
          "HealthCheckProtocol" => "HTTP",
          "HeathCheckPort" => 8088,
          "TargetGroupArn" => "target_group_arn",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :modify_target_group,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec modify_target_group(target_group_arn(), modify_target_group_opts()) :: ExAws.Operation.Query.t()
  def modify_target_group(target_group_arn, opts \\ []) do
    [{:target_group_arn, target_group_arn} | opts]
    |> build_request(:modify_target_group)
  end

  @doc """
  Modifies the specified attributes of the specified target group.

  ## Examples:

      iex> attributes = [{:hello, "test"}]
      [hello: "test"]
      iex> ExAws.ElasticLoadBalancingV2.modify_target_group_attributes("target_group_arn", attributes)
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "ModifyTargetGroupAttributes",
          "Attributes.member.1.Key" => "hello",
          "Attributes.member.1.Value" => "test",
          "TargetGroupArn" => "target_group_arn",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :modify_target_group_attributes,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec modify_target_group_attributes(target_group_arn(), target_group_attributes()) :: ExAws.Operation.Query.t()
  def modify_target_group_attributes(target_group_arn, attributes) do
    [{:target_group_arn, target_group_arn}, {:attributes, attributes}]
    |> build_request(:modify_target_group_attributes)
  end

  @doc """
  Registers the specified targets with the specified target group.

  You can register targets by instance ID or by IP address. If the
  target is an EC2 instance, it must be in the `running` state when you
  register it.

  By default, the load balancer routes requests to registered targets using
  the protocol and port for the target group. Alternatively, you can override
  the port for a target when you register it. You can register each EC2
  instance or IP address with the same target group multiple times using
  different ports.

  With a Network Load Balancer, you cannot register instances by instance ID
  if they have the following instance types: C1, CC1, CC2, CG1, CG2, CR1,
  CS1, G1, G2, HI1, HS1, M1, M2, M3, and T1. You can register instances of
  these types by IP address.

  To remove a target from a target group, use `deregister_targets/1`.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.register_targets("target_group_arn", ["target1", "target2"])
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "RegisterTargets",
          "TargetGroupArn" => "target_group_arn",
          "Targets.member.1" => "target1",
          "Targets.member.2" => "target2",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :register_targets,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec register_targets(target_group_arn(), target_descriptions()) :: ExAws.Operation.Query.t()
  def register_targets(target_group_arn, targets) do
    [{:target_group_arn, target_group_arn}, {:targets, targets}]
    |> build_request(:register_targets)
  end

  @doc """
  Removes the specified certificate from the specified secure listener.

  You can't remove the default certificate for a listener. To replace
  the default certificate, call `modify_listener/1`. To list the certificates
  for your listener, use `describe_listener_certificates/1`.

  ## Examples:

      iex> certificates = [%{certificate_arn: "certificate1_arn", is_default: true}, %{certificate_arn: "certificate2_arn"}]
      [
        %{certificate_arn: "certificate1_arn", is_default: true},
        %{certificate_arn: "certificate2_arn"}
      ]
      iex> ExAws.ElasticLoadBalancingV2.remove_listener_certificates("listener_arn", certificates)
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "RemoveListenerCertificates",
          "Certificates.member.1.CertificateArn" => "certificate1_arn",
          "Certificates.member.1.IsDefault" => true,
          "Certificates.member.2.CertificateArn" => "certificate2_arn",
          "ListenerArn" => "listener_arn",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :remove_listener_certificates,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec remove_listener_certificates(listener_arn(), certificates()) :: ExAws.Operation.Query.t()
  def remove_listener_certificates(listener_arn, certificates) do
    [{:listener_arn, listener_arn}, {:certificates, certificates}]
    |> build_request(:remove_listener_certificates)
  end

  @doc """
  Removes the specified tags from the specified Elastic Load Balancing
  resource.

  To list the current tags for your resources, use `describe_tags/1`.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.remove_tags(["resource_arn1", "resource_arn2"], ["tag1", "tag2"])
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "RemoveTags",
          "ResourceArns.member.1" => "resource_arn1",
          "ResourceArns.member.2" => "resource_arn2",
          "TagsKeys.1" => "tag1",
          "TagsKeys.2" => "tag2",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :remove_tags,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec remove_tags(resource_arns(), tag_keys()) :: ExAws.Operation.Query.t()
  def remove_tags(resource_arns, tag_keys) do
    [{:resource_arns, resource_arns}, {:tags_keys, tag_keys}]
    |> build_request(:remove_tags)
  end

  @doc """
  Sets the type of IP addresses used by the subnets of the specified
  Application Load Balancer or Network Load Balancer.

  *Note: Network Load Balancers must use `ipv4`*.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.set_ip_address_type("load_balancer_arn", "ipv4")
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "SetIpAddressType",
          "IpAddressType" => "ipv4",
          "LoadBalancerArn" => "load_balancer_arn",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :set_ip_address_type,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec set_ip_address_type(load_balancer_arn(), ip_address_type()) :: ExAws.Operation.Query.t()
  def set_ip_address_type(load_balancer_arn, ip_address_type) do
    [{:load_balancer_arn, load_balancer_arn}, {:ip_address_type, ip_address_type}]
    |> build_request(:set_ip_address_type)
  end

  @doc """
  Sets the priorities of the specified rules.

  You can reorder the rules as long as there are no priority conflicts
  in the new order. Any existing rules that you do not specify retain
  their current priority.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.set_rule_priorities([1,2,3])
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "SetRulePriorities",
          "RulePriorities.member.1" => 1,
          "RulePriorities.member.2" => 2,
          "RulePriorities.member.3" => 3,
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :set_rule_priorities,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec set_rule_priorities(rule_priorities :: [integer, ...]) :: ExAws.Operation.Query.t()
  def set_rule_priorities(rule_priorities) do
    [{:rule_priorities, rule_priorities}]
    |> build_request(:set_rule_priorities)
  end

  @doc """
  Associates the specified security groups with the specified Application
  Load Balancer.

  The specified security groups override the previously associated security
  groups.

  *Note: You can't specify a security group for a Network Load Balancer*.

  ## Examples:

      iex>  ExAws.ElasticLoadBalancingV2.set_security_groups("load_balancer_arn", ["security_group1", "security_group2"])
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "SetSecurityGroups",
          "LoadBalancerArn" => "load_balancer_arn",
          "SecurityGroups.member.1" => "security_group1",
          "SecurityGroups.member.2" => "security_group2",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :set_security_groups,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec set_security_groups(load_balancer_arn(), security_groups(), set_security_groups_opts()) ::
          ExAws.Operation.Query.t()
  def set_security_groups(load_balancer_arn, security_groups, opts \\ []) do
    [{:load_balancer_arn, load_balancer_arn}, {:security_groups, security_groups} | opts]
    |> build_request(:set_security_groups)
  end

  @doc """
  Enables the Availability Zone for the specified subnets for the specified
  Application Load Balancer.

  The specified subnets replace the previously enabled subnets.

  *Note: You can't change the subnets for a Network Load Balancer*.

  ## Examples:

      iex>  ExAws.ElasticLoadBalancingV2.set_subnets("load_balancer_arn", ["subnet1", "subnet2"])
      %ExAws.Operation.Query{
        path: "/",
        params: %{
          "Action" => "SetSubnets",
          "LoadBalancerArn" => "load_balancer_arn",
          "Subnets.member.1" => "subnet1",
          "Subnets.member.2" => "subnet2",
          "Version" => "2015-12-01"
        },
        content_encoding: "identity",
        service: :elasticloadbalancing,
        action: :set_subnets,
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
      }
  """
  @spec set_subnets(load_balancer_arn(), subnets(), set_subnets_opts()) :: ExAws.Operation.Query.t()
  def set_subnets(load_balancer_arn, subnets, opts \\ []) do
    opts
    |> keyword_to_map()
    |> Map.merge(%{
      load_balancer_arn: load_balancer_arn,
      subnets: subnets
    })
    |> build_request(:set_subnets)
  end

  ####################
  # Helper Functions #
  ####################
  defp build_request(opts, actions) when is_map(opts) do
    opts
    |> Map.to_list()
    |> build_request(actions)
  end

  defp build_request(opts, action) do
    opts
    |> Enum.flat_map(&format_param/1)
    |> request(action)
  end

  defp keyword_to_map(keyword) when is_list(keyword) do
    keyword
    |> Enum.into(%{}, fn {k, v} -> {k, v} end)
  end

  defp keyword_to_map(map) when is_map(map), do: map
  defp keyword_to_map(_), do: %{}

  defp request(params, action) do
    action_string = action |> Atom.to_string() |> Macro.camelize()

    %ExAws.Operation.Query{
      path: "/",
      params:
        params
        |> filter_nil_params
        |> Map.put("Action", action_string)
        |> Map.put("Version", @version),
      service: :elasticloadbalancing,
      action: action,
      parser: &V2Parser.parse/2
    }
  end

  defp format_param({:actions, actions}) do
    actions |> format(prefix: "Actions.member")
  end

  defp format_param({:attributes, attributes}) do
    attributes
    |> Enum.map(fn {key, value} -> [key: maybe_stringify(key), value: value] end)
    |> format(prefix: "Attributes.member")
  end

  defp format_param({:alpn_policy, alpn_policies}) do
    alpn_policies |> format(prefix: "AlpnPolicy.member")
  end

  defp format_param({:certificates, certificates}) do
    certificates |> format(prefix: "Certificates.member")
  end

  defp format_param({:conditions, conditions}) do
    conditions |> format(prefix: "Conditions.member")
  end

  defp format_param({:default_actions, actions}) do
    actions |> format(prefix: "DefaultActions.member")
  end

  defp format_param({:listener_arns, listener_arns}) do
    listener_arns |> format(prefix: "ListenerArns.member")
  end

  defp format_param({:load_balancer_arns, load_balancer_arns}) do
    load_balancer_arns |> format(prefix: "LoadBalancerArns.member")
  end

  defp format_param({:names, names}) do
    names |> format(prefix: "Names.member")
  end

  defp format_param({:trust_store_arns, trust_store_arns}) do
    trust_store_arns |> format(prefix: "TrustStoreArns.member")
  end

  defp format_param({:resource_arns, resource_arns}) do
    resource_arns |> format(prefix: "ResourceArns.member")
  end

  defp format_param({:rewrites, rewrites}) do
    rewrites |> format(prefix: "Rewrites.member")
  end

  defp format_param({:rule_arns, rule_arns}) do
    rule_arns |> format(prefix: "RuleArns.member")
  end

  defp format_param({:rule_priorities, rule_priorities}) do
    rule_priorities |> format(prefix: "RulePriorities.member")
  end

  defp format_param({:security_groups, security_groups}) do
    security_groups |> format(prefix: "SecurityGroups.member")
  end

  defp format_param({:subnets, subnets}) do
    subnets |> format(prefix: "Subnets.member")
  end

  defp format_param({:subnet_mappings, subnet_mappings}) do
    subnet_mappings |> format(prefix: "SubnetMappings.member")
  end

  defp format_param({:regex_values, regex_values}) do
    regex_values |> format(prefix: "RegexValues.member")
  end

  defp format_param({:values, values}) do
    values |> format(prefix: "Values.member")
  end

  defp format_param({:tags, tags}) do
    tags
    |> Enum.map(fn tag ->
      case is_map(tag) do
        true ->
          tag

        false ->
          {key, value} = tag
          %{key: maybe_stringify(key), value: value}
      end
    end)
    |> format(prefix: "Tags.member")
  end

  defp format_param({:tag_keys, tag_keys}) do
    tag_keys |> format(prefix: "TagKeys.member")
  end

  defp format_param({:targets, targets}) do
    targets |> format(prefix: "Targets.member")
  end

  defp format_param({:target_group_arns, target_group_arns}) do
    target_group_arns |> format(prefix: "TargetGroupArns.member")
  end

  defp format_param({:revocation_contents, revocation_contents}) do
    revocation_contents |> format(prefix: "RevocationContents.member")
  end

  defp format_param({:revocation_ids, revocation_ids}) do
    revocation_ids |> format(prefix: "RevocationIds.member")
  end

  defp format_param({:trust_store_arn, trust_store_arn}) do
    %{"TrustStoreArn" => trust_store_arn}
  end

  defp format_param({key, parameters}) do
    format([{key, parameters}])
  end
end
