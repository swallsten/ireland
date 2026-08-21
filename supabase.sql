-- Paste this whole file into the Supabase SQL Editor and press Run.
-- It creates the notes table and locks it down so visitors can read and add
-- notes but cannot edit or delete anyone else's.

create table if not exists public.comments (
  id          bigint generated always as identity primary key,
  created_at  timestamptz not null default now(),
  author      text not null check (char_length(author) between 1 and 40),
  section     text not null default 'general' check (char_length(section) <= 80),
  body        text not null check (char_length(body) between 1 and 2000)
);

create index if not exists comments_section_idx on public.comments (section, created_at);

alter table public.comments enable row level security;

drop policy if exists "anyone can read notes"  on public.comments;
drop policy if exists "anyone can add a note"  on public.comments;

create policy "anyone can read notes"
  on public.comments for select to anon using (true);

create policy "anyone can add a note"
  on public.comments for insert to anon with check (true);

-- Deliberately no update or delete policy. Nobody can wipe the thread from the
-- page. If you need to remove something, delete the row in the Table Editor.
