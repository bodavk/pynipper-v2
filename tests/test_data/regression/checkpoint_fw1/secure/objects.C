(:objects (
  :network-objects (
    :Gateway-A (:type (gateway) :ipaddr (192.0.2.1) :firewall (installed))
    :Gateways (:type (group) :members ((ReferenceObject (:Name (Gateway-A)))))
    :Admin-Networks (:type (network) :ipaddr (192.0.2.0) :netmask (255.255.255.0))
    :Internal-Networks (:type (network) :ipaddr (10.0.0.0) :netmask (255.0.0.0))
    :Web-Servers (:type (group) :members ((ReferenceObject (:Name (Web-01)))))
    :Web-01 (:type (host) :ipaddr (10.10.10.20))
  )
  :services (
    :SSH (:type (tcp) :port (22))
    :HTTPS (:type (tcp) :port (443))
  )
))
