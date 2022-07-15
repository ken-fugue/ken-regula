resource_type := "MULTIPLE"
managed_disks = fugue.resources("azurerm_managed_disk")
virtual_machines = fugue.resources("azurerm_virtual_machine")
data_disk_attachments = fugue.resources("azurerm_virtual_machine_data_disk_attachment")


# Find managed disks, and create a set of the CMK encrypted ones.

disk_is_encrypted_via_cmk(managed_disk) = ret {
  ret = managed_disk.disk_encryption_set_id != ""
}

disk_is_encrypted(managed_disk) = ret {
  managed_disk.encryption_settings[_].enabled
  ret = true
} else = ret {
  managed_disk.disk_encryption_set_id != null
  ret = true
} else = ret {
  ret = false
}

encrypted_managed_disks_via_cmk = {managed_disk_id |
  managed_disk = managed_disks[_]
  managed_disk_id = managed_disk.id
  disk_is_encrypted_via_cmk(managed_disk)
}

attached_data_disks[managed_disk_id] {
  # Attached as data disk directly.
  virtual_machine = virtual_machines[_]
  managed_disk_id = lower(virtual_machine.storage_data_disk[_].managed_disk_id)
} {
  # Attached as data disk through a
  # `azurerm_virtual_machine_data_disk_attachment`.
  disk_attachment = data_disk_attachments[_]
  lower(disk_attachment.managed_disk_id) = managed_disk_id
}

encrypted_managed_disks = {managed_disk_id |
  managed_disk = managed_disks[_]
  managed_disk_id = managed_disk.id
  disk_is_encrypted(managed_disk)
}


policy[j] {
  md = managed_disks[_]
  attached_data_disks[lower(md.id)]
  encrypted_managed_disks[md.id]
  lower(md.tags.vendormanaged) == "true"
  j = fugue.allow_resource(md)
} {
  md = managed_disks[_]
  attached_data_disks[lower(md.id)]
  not encrypted_managed_disks[md.id]
  j = fugue.deny_resource(md)
}

  md = managed_disks[_]
  attached_data_disks[lower(md.id)]
  encrypted_managed_disks[md.id]
  lower(md.tags.vendormanaged) == "true"
