/*
  # Fix Row Level Security Policies

  1. Security Updates
    - Add RLS policies for projects table to allow authenticated users to manage their own projects
    - Add RLS policies for searches table to allow authenticated users to manage their own searches
    - Add RLS policies for profiles table to allow authenticated users to read/update their own profile
    - Add RLS policies for candidates table to allow authenticated users to access candidates in their projects

  2. Policy Details
    - Projects: Users can create, read, update, and delete their own projects
    - Searches: Users can create, read, update, and delete their own searches
    - Profiles: Users can read and update their own profile
    - Candidates: Users can read candidates associated with their projects

  This migration ensures proper access control while allowing the application to function correctly.
*/

-- Enable RLS on all tables if not already enabled
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE searches ENABLE ROW LEVEL SECURITY;
ALTER TABLE candidates ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if they exist to avoid conflicts
DROP POLICY IF EXISTS "Users can read own profile" ON profiles;
DROP POLICY IF EXISTS "Users can update own profile" ON profiles;
DROP POLICY IF EXISTS "Users can insert own profile" ON profiles;

DROP POLICY IF EXISTS "Users can read own projects" ON projects;
DROP POLICY IF EXISTS "Users can create own projects" ON projects;
DROP POLICY IF EXISTS "Users can update own projects" ON projects;
DROP POLICY IF EXISTS "Users can delete own projects" ON projects;

DROP POLICY IF EXISTS "Users can read own searches" ON searches;
DROP POLICY IF EXISTS "Users can create own searches" ON searches;
DROP POLICY IF EXISTS "Users can update own searches" ON searches;
DROP POLICY IF EXISTS "Users can delete own searches" ON searches;

DROP POLICY IF EXISTS "Users can read candidates in their projects" ON candidates;
DROP POLICY IF EXISTS "Users can create candidates in their projects" ON candidates;
DROP POLICY IF EXISTS "Users can update candidates in their projects" ON candidates;
DROP POLICY IF EXISTS "Users can delete candidates in their projects" ON candidates;

-- Profiles table policies
CREATE POLICY "Users can read own profile"
  ON profiles
  FOR SELECT
  TO authenticated
  USING (auth.uid() = id);

CREATE POLICY "Users can update own profile"
  ON profiles
  FOR UPDATE
  TO authenticated
  USING (auth.uid() = id);

CREATE POLICY "Users can insert own profile"
  ON profiles
  FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = id);

-- Projects table policies
CREATE POLICY "Users can read own projects"
  ON projects
  FOR SELECT
  TO authenticated
  USING (auth.uid() = user_id);

CREATE POLICY "Users can create own projects"
  ON projects
  FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own projects"
  ON projects
  FOR UPDATE
  TO authenticated
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own projects"
  ON projects
  FOR DELETE
  TO authenticated
  USING (auth.uid() = user_id);

-- Searches table policies
CREATE POLICY "Users can read own searches"
  ON searches
  FOR SELECT
  TO authenticated
  USING (auth.uid() = user_id);

CREATE POLICY "Users can create own searches"
  ON searches
  FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own searches"
  ON searches
  FOR UPDATE
  TO authenticated
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own searches"
  ON searches
  FOR DELETE
  TO authenticated
  USING (auth.uid() = user_id);

-- Candidates table policies (users can access candidates in their projects)
CREATE POLICY "Users can read candidates in their projects"
  ON candidates
  FOR SELECT
  TO authenticated
  USING (
    project_id IN (
      SELECT id FROM projects WHERE user_id = auth.uid()
    )
  );

CREATE POLICY "Users can create candidates in their projects"
  ON candidates
  FOR INSERT
  TO authenticated
  WITH CHECK (
    project_id IN (
      SELECT id FROM projects WHERE user_id = auth.uid()
    )
  );

CREATE POLICY "Users can update candidates in their projects"
  ON candidates
  FOR UPDATE
  TO authenticated
  USING (
    project_id IN (
      SELECT id FROM projects WHERE user_id = auth.uid()
    )
  );

CREATE POLICY "Users can delete candidates in their projects"
  ON candidates
  FOR DELETE
  TO authenticated
  USING (
    project_id IN (
      SELECT id FROM projects WHERE user_id = auth.uid()
    )
  );