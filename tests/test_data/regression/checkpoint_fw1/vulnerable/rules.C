(:rule-base (
  :Network-Layer (
    :type (ordered-layer)
    :implicit-cleanup-action (drop)
    :rule-1 (
      :name ("Broad first")
      :src (Any) :dst (Any) :services (Any)
      :action (accept) :track (None) :install-on (Any)
    )
    :rule-2 (
      :name ("Shadowed deny")
      :src (ReferenceObject (:Name (Admin-Networks)))
      :dst (ReferenceObject (:Name (Web-Servers)))
      :services (ReferenceObject (:Name (HTTPS)))
      :action (drop) :track (Log) :install-on (Any)
    )
    :rule-3 (
      :name ("Redundant broad")
      :src (Any) :dst (Any) :services (Any)
      :action (accept) :track (Log) :install-on (Any)
    )
    :rule-4 (
      :name ("Expired exception")
      :src (ReferenceObject (:Name (Admin-Networks)))
      :dst (ReferenceObject (:Name (Web-Servers)))
      :services (ReferenceObject (:Name (HTTPS)))
      :action (accept) :track (Log) :expiration-date (2000-01-01)
      :install-on (ReferenceObject (:Name ("Policy Targets")))
    )
    :rule-5 (
      :name ("Legacy administration")
      :src (Any) :dst (ReferenceObject (:Name (Web-Servers)))
      :services (ReferenceObject (:Name (Legacy-Admin)))
      :action (accept) :track (None)
      :install-on (ReferenceObject (:Name ("Policy Targets")))
    )
    :rule-6 (
      :name (Cleanup)
      :src (Any) :dst (Any) :services (Any)
      :action (drop) :track (Log)
      :install-on (ReferenceObject (:Name ("Policy Targets")))
    )
  )
))
