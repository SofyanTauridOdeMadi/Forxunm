
CREATE TABLE `users` (
  `id` int(11) NOT NULL,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `email` varchar(255) DEFAULT NULL,
  `bio` text DEFAULT NULL,
  `profile_picture_url` varchar(255) DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  `failed_login_attempts` int(11) DEFAULT 0,
  `lockout_until` datetime DEFAULT NULL,
  `totp_secret` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

INSERT INTO `users` VALUES
(4, 'stom', '3b9a1a16c4f7466e6d3e8a797b34d06eb418e224f94b6b37b6c41c335b79b952', 'sofyantauridodemadi@gmail.com', 'Dari Kelompok 4 Cuy, Paling GG\nSofyan Taurid Ode Madi, JDFB', '1746338868500-FT_DIRI_220210502019.jpg', '2025-05-03 05:05:47', '2025-05-04 06:57:37', 0, NULL, 'JVIHORRJORXW4TLVFIZFAJR6FA2VQYKQ'),
(5, 'Indira', '3b9a1a16c4f7466e6d3e8a797b34d06eb418e224f94b6b37b6c41c335b79b952', NULL, NULL, NULL, '2025-05-03 16:10:14', '2025-05-03 16:10:14', 0, NULL, 'MIXSS4DBHIYUW5JZOZDHCTDLGN4XQOSR'),

CREATE TABLE `threads` (
  `thread_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `title` varchar(255) NOT NULL,
  `content` text DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `upvotes` int(11) DEFAULT 0,
  `is_deleted` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

INSERT INTO `threads` VALUES
(1, 2, 'Ini forum apa ?', 'Uji coba aja yah', '2025-03-02 16:12:27', 6, 0),
(2, 5, 'Apa Itu Serangan CSRF?', 'Cross- Cross-Site Request Forgery (CSRF) adalah jenis serangan ...', '2025-03-03 15:02:01', 10003, 0),
(3, 2, '[BERTANYA] Bagaimana cara hacking ?', 'saya ingin belajar hacking !!! tolong ajarin saya !!!', '2025-03-02 16:12:27', 9, 0),
(4, 1, 'Uji Coba', 'tes aja gitu', '2025-04-26 11:33:45', 2, 0),
(5, 1, 'a', 'a', '2025-04-29 09:53:59', 0, 0),
(6, 4, 'Uji Coba', 'Halo sudah berhasil Cuyyy', '2025-05-03 13:45:01', 5, 0),
(7, 4, 'a', 'a', '2025-05-03 15:21:56', 0, 0);

CREATE TABLE `replies` (
  `reply_id` int(11) NOT NULL,
  `thread_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `content` text NOT NULL,
  `is_deleted` tinyint(1) DEFAULT 0,
  `created_at` timestamp NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

INSERT INTO `replies` VALUES
(1, 6, 4, 'halo', 0, '2025-05-03 07:12:23'),
(3, 7, 4, 'a', 0, '2025-05-03 07:22:00');

CREATE TABLE `messages` (
  `id` int(11) NOT NULL,
  `username` varchar(255) NOT NULL,
  `message` text NOT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  `aes_key` varchar(64) DEFAULT NULL,
  `iv` varchar(32) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

INSERT INTO `messages` VALUES
(22, 'stom', '644ba570805bd2b0733c6c597ee7640e', '2025-05-03 15:23:08', NULL, NULL),
(23, 'stom', '68d0a78eea46dbb43fd784fccda25d33', '2025-05-03 15:24:17', NULL, NULL),
(26, 'stom', '849a084a1fa9658ae1d295a3a92e78409374523682ee2c9381d359574e9ef17e', '2025-05-03 16:10:34', NULL, NULL),
(27, 'stom', '644ba570805bd2b0733c6c597ee7640e', '2025-05-03 22:13:53', NULL, NULL),
(28, 'Indira', '626e528dd6e48bd3956d69169b16b3d4', '2025-05-04 00:14:35', NULL, NULL),
(29, 'stom', '9c56d4b245aa4eaf283841b67601e948', '2025-05-04 14:03:11', NULL, NULL);
