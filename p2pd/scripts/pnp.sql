-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: localhost
-- Generation Time: Jun 07, 2024 at 07:30 AM
-- Server version: 10.5.23-MariaDB-0+deb11u1
-- PHP Version: 7.4.33

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `pnp`
--

-- --------------------------------------------------------

--
-- Table structure for table `ipv4s`
--

CREATE TABLE `ipv4s` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `v4_val` int(10) UNSIGNED NOT NULL,
  `timestamp` bigint(20) UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `ipv6s`
--

CREATE TABLE `ipv6s` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `v6_glob_main` int(10) UNSIGNED NOT NULL,
  `v6_glob_extra` smallint(5) UNSIGNED NOT NULL,
  `v6_lan_id` smallint(5) UNSIGNED NOT NULL,
  `v6_iface_id` bigint(20) UNSIGNED NOT NULL,
  `timestamp` bigint(20) UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `names`
--

CREATE TABLE `names` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `name` varbinary(50) NOT NULL,
  `value` varbinary(500) NOT NULL,
  `owner_pub` binary(33) NOT NULL,
  `af` tinyint(3) UNSIGNED NOT NULL,
  `ip_id` bigint(20) UNSIGNED NOT NULL,
  `timestamp` bigint(20) UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `ipv4s`
--
ALTER TABLE `ipv4s`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `v4_val` (`v4_val`);

--
-- Indexes for table `ipv6s`
--
ALTER TABLE `ipv6s`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `v6_val` (`v6_glob_main`,`v6_glob_extra`,`v6_lan_id`,`v6_iface_id`);

--
-- Indexes for table `names`
--
ALTER TABLE `names`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `name` (`name`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `ipv4s`
--
ALTER TABLE `ipv4s`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=308;

--
-- AUTO_INCREMENT for table `ipv6s`
--
ALTER TABLE `ipv6s`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=383;

--
-- AUTO_INCREMENT for table `names`
--
ALTER TABLE `names`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=1210;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
