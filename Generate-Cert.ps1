      # Generate a self-signed certificate, save it to the current user's personal store
      $displayName = "TestCreate"
      Write-Host "Creating the client certificate for application $displayName"
      $certificate=New-SelfSignedCertificate -Subject CN=$displayName `
                                             -CertStoreLocation "Cert:\CurrentUser\My" `
                                             -KeyExportPolicy Exportable `
                                             -KeySpec Signature