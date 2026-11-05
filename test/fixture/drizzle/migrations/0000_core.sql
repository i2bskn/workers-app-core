CREATE TABLE `sessions` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`family_id` text NOT NULL,
	`auth_mode` text NOT NULL,
	`token_hash` text NOT NULL,
	`family_expires_at` integer NOT NULL,
	`created_at` integer NOT NULL,
	`rotated_at` integer,
	`rotated_to` text,
	`revoked_at` integer,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE no action,
	CONSTRAINT "sessions_auth_mode_check" CHECK("sessions"."auth_mode" IN ('oidc', 'password'))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `sessions_token_hash_unique` ON `sessions` (`token_hash`);--> statement-breakpoint
CREATE INDEX `sessions_user_id_idx` ON `sessions` (`user_id`);--> statement-breakpoint
CREATE INDEX `sessions_family_id_idx` ON `sessions` (`family_id`);--> statement-breakpoint
CREATE TABLE `users` (
	`id` text PRIMARY KEY NOT NULL,
	`email` text NOT NULL,
	`name` text,
	`role` text NOT NULL,
	`password_hash` text,
	`oidc_issuer` text,
	`oidc_subject` text,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL,
	`last_login_at` integer,
	`mcp_revoked_at` integer,
	CONSTRAINT "users_role_check" CHECK("users"."role" IN ('admin', 'member'))
);
--> statement-breakpoint
CREATE UNIQUE INDEX `users_email_unique` ON `users` (`email`);--> statement-breakpoint
CREATE UNIQUE INDEX `users_oidc_issuer_subject_unique` ON `users` (`oidc_issuer`,`oidc_subject`);--> statement-breakpoint
CREATE TABLE `user_notes` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`user_id` text NOT NULL,
	`note` text NOT NULL
);
