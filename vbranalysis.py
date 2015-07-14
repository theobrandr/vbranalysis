import binascii

def program_start():
	print "This program will interpret FAT, FAT32, EXFAT, and NTFS VBR Data."
	print "Which kind of VBR data do you need interpreted? \n"
	print "(1):FAT \n(2):FAT32 \n(3):EXFAT \n(4):NTFS"

	vbr_type = raw_input("> ")

	if "1" in vbr_type:
		fat_analysis()
	elif "2" in vbr_type:
		fat_thirtytwo_analysis()
	elif "3" in vbr_type:
		exfat_analysis()
	elif "4" in vbr_type:
		ntfs_analysis()
	else:
		print "Try choosing again!"
		program_start()

def fat_analysis():
	#Get the FAT VBR bytes as a user input
	fat_user_data = raw_input("Paste the 512 bytes of FAT VBR data here ---> ")
	
	#sort the user input into groups of two's, each will represent a byte
	fat_user_data_sort = map(''.join, zip(*[iter(fat_user_data)]*2))
	
	#Take the corresponding data and associate it with named variables
	jump_code = fat_user_data_sort[0:3]
	print "Offset 0-2 : Jump Code"
	print "".join( jump_code)
	
	oem_name = fat_user_data_sort[3:11]
	print "Offset 3-10 : OEM Name"
	print "".join( oem_name),"-->",binascii.unhexlify(bytearray(''.join(oem_name)))
	#print then convert the data from groups of two back to single and then from hex to ASCII Text
	
	bytes_per_sector = fat_user_data_sort[11:13]
	bytes_per_sector_rev = ''.join(bytes_per_sector[::-1]) #reverse the string and assign to a variable
	print "Offset 11-12 : Number of bytes per sector"
	print "".join( bytes_per_sector), "-->", int(bytes_per_sector_rev, 16)
	#print the data and then convert the data from hex to decimal
	
	sectors_per_cluster = fat_user_data_sort[13]
	print "Offset 13 : Number of Sectors per Cluster"
	print "".join( sectors_per_cluster), "-->", int(''.join(sectors_per_cluster), 16)
	
	num_reserved_sectors = fat_user_data_sort[14:16]
	num_reserved_sectors_rev = ''.join(num_reserved_sectors[::-1])
	print "Offset 14-15 : Number of Reserved Sectors"
	print "".join( num_reserved_sectors), "-->", int(num_reserved_sectors_rev, 16)
	
	num_copies_fat = fat_user_data_sort[16]
	print "Offset 16 : Number of Copies of File Allocation Table"
	print "".join( num_copies_fat), "-->",int(''.join(num_copies_fat), 16)
	
	num_entry_rd = fat_user_data_sort[17:19]
	num_entry_rd_rev = ''.join(num_entry_rd[::-1])
	print "Offset 17-18 : Number of entries allowed in the root directory"
	print "".join( num_entry_rd),"-->",int(num_entry_rd_rev,16)

	num_sectors_part = fat_user_data_sort[19:21]
	num_sectors_part_rev = ''.join(num_sectors_part[::-1])
	print "Offset 19-20 : Number of sectors in the partition"
	print "".join( num_sectors_part),"-->",int(num_sectors_part_rev,16)
	
	media_descr = fat_user_data_sort[21]
	print "Offset 21 : Media Descriptor"
	print "".join( media_descr)
	
	num_sectors_fat = fat_user_data_sort[22:24]
	num_sectors_fat_rev = ''.join(num_sectors_fat[::-1])
	print "Offset 22-23 : Number of sectors per FAT"
	print "".join( num_sectors_fat),"-->",int(num_sectors_fat_rev,16)
	
	num_sectors_track = fat_user_data_sort[24:26]
	num_sectors_track_rev = ''.join(num_sectors_track[::-1])
	print "Offset 24-25 : Number of sectors per track"
	print "".join(num_sectors_track ),"-->",int(num_sectors_track_rev,16)
	
	num_heads = fat_user_data_sort[26:28]
	num_heads_rev = ''.join(num_heads[::-1])
	print "Offset 26-27 : Number of Heads"
	print "".join(num_heads),"-->", int(num_heads_rev,16)
	
	num_hidden_sectors = fat_user_data_sort[28:32]
	num_hidden_sectors_rev = ''.join(num_hidden_sectors[::-1])
	print "Offsets 28-31 : Number of hidden sectors"
	print "".join(num_hidden_sectors),"-->", int(num_hidden_sectors_rev,16)
	
	total_num_sectors = fat_user_data_sort[32:36]
	total_num_sectors_rev = ''.join(total_num_sectors[::-1])
	print "Offsets 32-35 : Total number of sectors in the partition"
	print "".join(total_num_sectors),"-->", int(total_num_sectors_rev,16)
	
	logical_drive_num = fat_user_data_sort[36]
	print "Offset 36 : Logical Drive Number"
	print "".join(logical_drive_num)
	
	reserved_byte = fat_user_data_sort[37]
	print "Offset 37 : Reserved"
	print "".join(reserved_byte)
	
	extended_signature = fat_user_data_sort[38]
	print "Offset 38 : Extended Signature"
	print "".join(extended_signature)
	
	vol_serial_num = fat_user_data_sort[39:43]
	print "Offset 39-42 : Volume Serial Number"
	print "".join(vol_serial_num)
	
	volume_label = fat_user_data_sort[43:54]
	print "Offset 43-53 : Volume Label"
	print "".join(volume_label),"-->",binascii.unhexlify(bytearray(''.join(volume_label)))
	
	file_system_type = fat_user_data_sort[54:62]
	print "Offset 54-61 : File System Type"
	print "".join(file_system_type),"-->",binascii.unhexlify(bytearray(''.join(file_system_type)))
	
	bootstrap_code = fat_user_data_sort[62:510]
	print "Offset 62-509 : Boostrap Code"
	print "".join(bootstrap_code)
	
	vbr_signature = fat_user_data_sort[510:512]
	print "Offset 510-511 : VBR Signature"
	print "".join(vbr_signature)


def fat_thirtytwo_analysis():
	#Get the FAT32 VBR bytes as a user input
	fat_thirtytwo = raw_input("Paste the 512 bytes of FAT32 VBR data here ---> ")
	
	fat_thirtytwo_sorted = map(''.join, zip(*[iter(fat_thirtytwo)]*2))
	#sort the user input into groups of two's, each will represent a byte
	
	#Take the corresponding data and associate it with named variables
	jump_code = fat_thirtytwo_sorted[0:3]
	print "Offset 0-2 : Jump Code"
	print "".join( jump_code)
	
	oem_name = fat_thirtytwo_sorted[3:11]
	print "Offset 3-10 : OEM Name"
	print "".join( oem_name),"-->",binascii.unhexlify(bytearray(''.join(oem_name)))
	
	bytes_per_sector = fat_thirtytwo_sorted[11:13]
	bytes_per_sector_rev = ''.join(bytes_per_sector[::-1])
	print "Offset 11-12 : Number of bytes per sector"
	print "".join( bytes_per_sector), "-->", int(bytes_per_sector_rev, 16)
	
	sectors_per_cluster = fat_thirtytwo_sorted[13]
	print "Offset 13 : Number of Sectors per Cluster"
	print "".join( sectors_per_cluster), "-->", int(''.join(sectors_per_cluster), 16)
	
	num_reserved_sectors = fat_thirtytwo_sorted[14:16]
	num_reserved_sectors_rev = ''.join(num_reserved_sectors[::-1])
	print "Offset 14-15 : Number of Reserved Sectors"
	print "".join( num_reserved_sectors), "-->", int(num_reserved_sectors_rev, 16)
	
	num_copies_fat = fat_thirtytwo_sorted[16]
	print "Offset 16 : Number of Copies of File Allocation Table"
	print "".join( num_copies_fat), "-->", int(''.join(num_copies_fat), 16)
	
	num_entry_rd = fat_thirtytwo_sorted[17:19]
	print "Offset 17-18 : Number of entries allowed in the root directory"
	print "".join( num_entry_rd)
	
	num_sectors_partition_small = fat_thirtytwo_sorted[19:21]
	print "Offset 19-20 : Number of sectors in the partition - Small"
	print "".join( num_sectors_partition_small)
	
	media_descr = fat_thirtytwo_sorted[21]
	print "Offset 21 : Media Descriptor"
	print "".join( media_descr)
	
	num_sectors_fat_small = fat_thirtytwo_sorted[22:24]
	print "Offset 22-23 : Number of sectors per FAT"
	print "".join( num_sectors_fat_small)
	
	num_sectors_track = fat_thirtytwo_sorted[24:26]
	num_sectors_track_rev = ''.join(num_sectors_track[::-1])
	print "Offset 24-25 : Number of sectors per track"
	print "".join(num_sectors_track),"-->", int(num_sectors_track_rev,16)
	
	num_heads = fat_thirtytwo_sorted[26:28]
	num_heads_rev = ''.join(num_heads[::-1])
	print "Offset 26-27 : Number of Heads"
	print "".join(num_heads),"-->", int(num_heads_rev,16)
	
	num_hidden_sectors = fat_thirtytwo_sorted[28:32]
	num_hidden_sectors_rev = ''.join(num_hidden_sectors[::-1])
	print "Offsets 28-31 : Number of hidden sectors"
	print "".join(num_hidden_sectors), "-->", int(num_hidden_sectors_rev,16)
	
	num_sectors_partition_large = fat_thirtytwo_sorted[32:36]
	num_sectors_partition_large_rev = ''.join(num_sectors_partition_large[::-1])
	print "Offsets 32-35 : Total number of sectors in the partition - Larger than Offset 19-20"
	print "".join(num_sectors_partition_large), "-->", int(num_sectors_partition_large_rev,16)
	
	sectors_per_fat_large = fat_thirtytwo_sorted[36:40]
	sectors_per_fat_large_rev = ''.join(sectors_per_fat_large[::-1])
	print "Offsets 36-39 : Sectors per Fat"
	print "".join(sectors_per_fat_large),"-->", int(sectors_per_fat_large_rev,16)
	
	mirror_flag = fat_thirtytwo_sorted[40:42]
	print "Offset 40-41: Mirror Flag"
	print "".join(mirror_flag)
	
	file_system_ver = fat_thirtytwo_sorted[42:44]
	print "Offset 42-43 : File System Version"
	print "".join(file_system_ver)
	
	rd_clust_loc = fat_thirtytwo_sorted[44:48]
	rd_clust_loc_rev = ''.join(rd_clust_loc[::-1])
	print "Offset 44-47 : First Cluster location of Root Directory "
	print "".join(rd_clust_loc),"-->", int(rd_clust_loc_rev,16)
	
	fs_info_sect = fat_thirtytwo_sorted[48:50]
	fs_info_sect_rev = ''.join(fs_info_sect[::-1])
	print "Offset 48-49 : FS Information Sector"
	print "".join(fs_info_sect),"-->",int(fs_info_sect_rev,16)
	
	bkup_boot_sect = fat_thirtytwo_sorted[50:52]
	bkup_boot_sect_rev = ''.join(bkup_boot_sect[::-1])
	print "Offset 50-51 : Backup Boot Sector"
	print "".join(bkup_boot_sect),"-->",int(bkup_boot_sect_rev,16)
	
	reserved_fivetwo = fat_thirtytwo_sorted[52:64]
	print "Offset 52-63 : Reserved"
	print "".join(reserved_fivetwo)
	
	logical_drive_num = fat_thirtytwo_sorted[64]
	print "Offset 64 : Logical Drive Number"
	print "".join(logical_drive_num)
	
	reserved_sixfive = fat_thirtytwo_sorted[65]
	print "Offset 65 : Reserved"
	print "".join(reserved_sixfive)
	
	extended_sig_sixsix = fat_thirtytwo_sorted[66]
	print "Offset 66 : Extended Signature"
	print "".join(extended_sig_sixsix)
	
	serial_num_part = fat_thirtytwo_sorted[67:71]
	print "Offset 67-70 : Serial Number of Partition"
	print "".join(serial_num_part)
	
	vol_label = fat_thirtytwo_sorted[71:82]
	print "Offset 71-81 : Volume Label"
	print "".join(vol_label),"-->",binascii.unhexlify(bytearray(''.join(vol_label)))
	
	file_system_type = fat_thirtytwo_sorted[82:90]
	print "Offset 82-89 : File System Type"
	print "".join(file_system_type),"-->",binascii.unhexlify(bytearray(''.join(file_system_type)))
	
	bootstrap_code = fat_thirtytwo_sorted[90:510]
	print "Offset 90-511 : Bootstrap Code"
	print "".join(bootstrap_code)
	
	vbr_signature = fat_thirtytwo_sorted[510:512]
	print "Offset 510-511 : VBR Signature"
	print "".join(vbr_signature)

def exfat_analysis():
	#Get the EXFAT VBR bytes as a user input
	exfat_user_data = raw_input("Paste the 512 bytes of EXFAT VBR data here ---> ")
	
	exfat_user_data_sort = map(''.join, zip(*[iter(exfat_user_data)]*2))
	#sort the user input into groups of two's, each will represent a byte
	
	#Take the corresponding data and associate it with corresponding named variables
	jump_code = exfat_user_data_sort[0:3]
	print "Offset 0-2 : Jump Code"
	print "".join( jump_code)
	
	oem_name = exfat_user_data_sort[3:11]
	print "Offset 3-10 : OEM ID"
	print "".join( oem_name),"-->",binascii.unhexlify(bytearray(''.join(oem_name)))
	
	reserved_bytes_eleven = exfat_user_data_sort[11:64]
	print "Offset 11-63 : Reserved"
	print "".join( reserved_bytes_eleven)
	
	part_sector_offset = exfat_user_data_sort[64:72]
	print "Offset 64-71 : Partition Sector Offset"
	print "".join( part_sector_offset)
	
	size_totvol_sectors = exfat_user_data_sort[72:80]
	print "Offset 72-79 : Size of Total Volume in Sectors"
	print "".join( size_totvol_sectors)
	
	sector_address_first_fat = exfat_user_data_sort[80:84]
	print "Offset 80-83 : Sector Address of First FAT"
	print "".join( sector_address_first_fat)
	
	size_fat_sectors = exfat_user_data_sort[84:88]
	print "Offset 84-87 : Size of FAT in Sectors"
	print "".join( size_fat_sectors)
	
	sector_addr_data_reg = exfat_user_data_sort[88:92]
	print "Offset 88-91 :Sector Address of Data Region"
	print "".join( sector_addr_data_reg)
	
	num_cluster_data_reg = exfat_user_data_sort[92:96]
	print "Offset 92-95 : Number of Clusters in Data Region"
	print "".join( num_cluster_data_reg )
	
	cluster_addr_root_dir = exfat_user_data_sort[96:100]
	print "Offset 96-99 : Cluster Address of Root Directory"
	print "".join( cluster_addr_root_dir)
	
	vol_serial_num = exfat_user_data_sort[100:104]
	print "Offset 100-103 : Volume Serial Number"
	print "".join( vol_serial_num)
	
	fs_revision = exfat_user_data_sort[104:106]
	print "Offset 104-105 : File System Revision"
	print "".join( fs_revision)
	
	vol_flag = exfat_user_data_sort[106:108]
	print "Offsets 106-107 : Volume Flags"
	print "".join( vol_flag)
	
	bytes_per_sector = exfat_user_data_sort[108]
	print "Offsets 108 : Bytes per Sector"
	print "".join( bytes_per_sector)
	
	sectors_per_cluster = exfat_user_data_sort[109]
	print "Offsets 109 : Sectors per Cluster"
	print "".join( sectors_per_cluster)
	
	num_fats = exfat_user_data_sort[110]
	print "Offset 110: Number of FATS"
	print "".join( num_fats)
	
	used_int = exfat_user_data_sort[111]
	print "Offset 111 : Used by INT13"
	print "".join(used_int)
	
	perc_data_region_use = exfat_user_data_sort[112]
	print "Offset 112 : Percentage of Data Region in Use"
	print "".join( perc_data_region_use)
	
	reserved_oneonethree= exfat_user_data_sort[113]
	print "Offset 113 : Reserved"
	print "".join( reserved_oneonethree)
	
	bootstrap_code = exfat_user_data_sort[103:510]
	print "Offset 113-509 : Bootstrap Code"
	print "".join( bootstrap_code)
	
	vbr_signature = exfat_user_data_sort[510:512]
	print "Offset 510-511 : VBR Signature"
	print "".join( vbr_signature)



def ntfs_analysis():
	#Get the NTFS VBR bytes as a user input
	ntfs_user_data = raw_input("Paste the 512 bytes of NTFS $Boot data here ---> ")
	
	ntfs_user_data_sort = map(''.join, zip(*[iter(ntfs_user_data)]*2))
	#sort the user input into groups of two's, each will represent a byte
	
	#Take the corresponding data and associate it with corresponding named variables
	jump_code = ntfs_user_data_sort[0:3]
	print "Offset 0-2 : Jump Code"
	print "".join(jump_code)
	
	oem_name = ntfs_user_data_sort[3:11]
	print "Offset 3-10 : OEM Name"
	print "".join( oem_name),"-->",binascii.unhexlify(bytearray(''.join(oem_name)))
	
	bytes_per_sector = ntfs_user_data_sort[11:13]
	bytes_per_sector_rev = ''.join(bytes_per_sector[::-1])
	print "Offset 11-12 : Bytes per Sector"
	print "".join(bytes_per_sector), "-->", int(bytes_per_sector_rev, 16)
	
	sectors_per_cluster = ntfs_user_data_sort[13]
	print "Offset 13 : Sectors Per Cluster"
	print "".join(sectors_per_cluster), "-->",int(sectors_per_cluster,16)
	
	reserved_sectors = ntfs_user_data_sort[14:16]
	print "Offset 14-15 : Reserved Sectors"
	print "".join(reserved_sectors)
	
	value_zero = ntfs_user_data_sort[16:21]
	print "Offset 16-20 : Values must be 0x00"
	print "".join(value_zero )
	
	media_descriptor = ntfs_user_data_sort[21]
	print "Offset 21 : Media Descriptor"
	print "".join(media_descriptor)
	
	value_zero_two = ntfs_user_data_sort[22:24]
	print "Offset 22-23 : Values must be 0x00"
	print "".join(value_zero_two)
	
	not_used_checked = ntfs_user_data_sort[24:32]
	print "Offset 24-31 : Not Used in NTFS and not Checked"
	print "".join(not_used_checked)
	
	value_zero_three = ntfs_user_data_sort[32:36]
	print "Offset 32-35 : Values must be 0x00"
	print "".join(value_zero_three)
	
	not_used_ntfs = ntfs_user_data_sort[36:40]
	print "Offset 36-39 : Not used in NTFS"
	print "".join(not_used_ntfs)
	
	total_sect_part = ntfs_user_data_sort[40:48]
	total_sect_part_rev = ''.join(total_sect_part[::-1])
	print "Offset 40-47 : Total Sectors in Partition"
	print "".join(total_sect_part), "-->", int(total_sect_part_rev,16)
	
	start_cluster_num_mft = ntfs_user_data_sort[48:56]
	start_cluster_num_mft_rev = ''.join(start_cluster_num_mft[::-1])
	print "Offsets 48-55 : Starting Cluster number for $MFT"
	print "".join(start_cluster_num_mft), "-->", int(start_cluster_num_mft_rev,16)
	
	start_cluster_num_mft_mir = ntfs_user_data_sort[56:64]
	start_cluster_num_mft_mir_rev = ''.join(start_cluster_num_mft_mir[::-1])
	print "Offsets 56-63 : Starting Cluster number for $MFT Mirr"
	print "".join(start_cluster_num_mft_mir), "-->", int(start_cluster_num_mft_mir_rev,16)
	
	cluster_per_mft = ntfs_user_data_sort[64]
	print "Offsets 64 : Clusters per $MFT Record"
	print "".join(cluster_per_mft)
	
	not_used_ntfs_two = ntfs_user_data_sort[65:68]
	print "Offset 65-67: Not used by NTFS"
	print "".join(not_used_ntfs_two)
	
	clusters_index_buffer = ntfs_user_data_sort[68]
	print "Offset 68 : Cluster per index buffer"
	print "".join(clusters_index_buffer)
	
	not_used_ntfs_three = ntfs_user_data_sort[69:72]
	print "Offset 69-71 : Not used in NTFS"
	print "".join(not_used_ntfs_three)
	
	vol_serial_num = ntfs_user_data_sort[72:80]
	print "Offset 72-79 : Volume Serial Number"
	print "".join(vol_serial_num)
	
	not_used_ntfs_four = ntfs_user_data_sort[80:84]
	print "Offset 80-83 : Not used in NTFS"
	print "".join(not_used_ntfs_four)
	
	bootstrap_code = ntfs_user_data_sort[84:510]
	print "Offset 120-509 : Bootstrap Code"
	print "".join( bootstrap_code)
	
	vbr_signature = ntfs_user_data_sort[510:512]
	print "Offset 510-511 : VBR Signature"
	print "".join(vbr_signature)

program_start()
