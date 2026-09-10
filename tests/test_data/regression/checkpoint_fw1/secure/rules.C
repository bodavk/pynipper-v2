(:rule-base (
  :Network-Layer (
    :type (ordered-layer)
    :implicit-cleanup-action (drop)
    :rule-1 (
      :name ("Admin access")
      :src (ReferenceObject (:Name (Admin-Networks)))
      :dst (ReferenceObject (:Name (Gateways)))
      :services (ReferenceObject (:Name (SSH)))
      :action (accept) :track (Log)
      :install-on (ReferenceObject (:Name ("Policy Targets")))
    )
    :rule-2 (
      :name (Stealth)
      :src (Any) :dst (ReferenceObject (:Name (Gateways)))
      :services (Any) :action (drop) :track (Alert)
      :install-on (ReferenceObject (:Name ("Policy Targets")))
    )
    :rule-3 (
      :name ("Publish web")
      :src (ReferenceObject (:Name (Internal-Networks)))
      :dst (ReferenceObject (:Name (Web-Servers)))
      :services (ReferenceObject (:Name (HTTPS)))
      :action (accept) :track (Log)
      :install-on (ReferenceObject (:Name ("Policy Targets")))
    )
    :rule-4 (
      :name (Cleanup)
      :src (Any) :dst (Any) :services (Any)
      :action (drop) :track (Log)
      :install-on (ReferenceObject (:Name ("Policy Targets")))
    )
  )
))
