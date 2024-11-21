class Ext4SuperBlock:
    def __init__(self):
        self.s_inodes_count = 0
        self.s_blocks_count_lo = 0
        self.s_r_blocks_count_lo = 0
        self.s_free_blocks_count_lo = 0
        self.s_free_inodes_count = 0
        self.s_first_data_block = 0
        self.s_log_block_size = 0
        self.s_log_cluster_size = 0
        self.s_blocks_per_group = 0
        self.s_clusters_per_group = 0
        self.s_inodes_per_group = 0
        self.s_mtime = 0
        self.s_wtime = 0
        self.s_mnt_count = 0
        self.s_max_mnt_count = 0
        self.s_magic = 0
        self.s_state = 0
        self.s_errors = 0
        self.s_minor_rev_level = 0
        self.s_lastcheck = 0
        self.s_checkinterval = 0
        self.s_creator_os = 0
        self.s_rev_level = 0
        self.s_def_resuid = 0
        self.s_def_resgid = 0
        self.s_first_ino = 0
        self.s_inode_size = 0
        self.s_block_group_nr = 0
        self.s_feature_compat = 0
        self.s_feature_incompat = 0
        self.s_feature_ro_compat = 0
        self.s_uuid = bytearray(16)
        self.s_volume_name = bytearray(16)
        self.s_last_mounted = bytearray(64)
        self.s_algorithm_usage_bitmap = 0
        self.s_prealloc_blocks = 0
        self.s_prealloc_dir_blocks = 0
        self.s_reserved_gdt_blocks = 0
        self.s_journal_uuid = bytearray(16)
        self.s_journal_inum = 0
        self.s_journal_dev = 0
        self.s_last_orphan = 0
        self.s_hash_seed = [0, 0, 0, 0]
        self.s_def_hash_version = 0
        self.s_jnl_backup_type = 0
        self.s_desc_size = 0
        self.s_default_mount_opts = 0
        self.s_first_meta_bg = 0
        self.s_mkfs_time = 0
        self.s_blocks_count_hi = 0
        self.s_r_blocks_count_hi = 0
        self.s_free_blocks_count_hi = 0
        self.s_min_extra_isize = 0
        self.s_want_extra_isize = 0
        self.s_flags = 0
        self.s_raid_stride = 0
        self.s_mmp_interval = 0
        self.s_mmp_block = 0
        self.s_raid_stripe_width = 0

    def get_volume_name(self):
        return bytes.decode(s_volume_name)

    def is_inline_data(self, s_inodes_count=0)
        return int.from_bytes(s_inodes_count).decode('utf-8')

    def isValid(self):
        return (s_magic == Ext4Constants.SUPER_BLOCK_MAGIC
