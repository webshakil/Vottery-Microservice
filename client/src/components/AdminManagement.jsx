import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';

const AdminManagement = () => {
  const { userData, isAdmin } = useAuth();
  const [users, setUsers] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [showUserModal, setShowUserModal] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterRole, setFilterRole] = useState('all');
  const [filterType, setFilterType] = useState('all');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Mock users data for Milestone 1 demonstration
  useEffect(() => {
    const mockUsers = [
      {
        id: 1,
        sngine_email: 'chumkysk@gmail.com',
        sngine_phone: '+8801768001023',
        first_name: 'Chumky',
        last_name: 'Sk',
        user_type: 'voter',
        admin_role: 'analyst',
        subscription_status: 'free',
        status: 'active',
        created_at: '2025-08-20T08:49:41.516Z',
        last_login: '2025-08-30T10:30:00.000Z',
        country: 'Bangladesh',
        city: 'Chittagong',
        user_age: 25,
        user_gender: 'Male',
        email_verified_at: '2025-08-20T08:50:41.516Z',
        phone_verified_at: '2025-08-20T08:52:41.516Z',
        biometric_registered_at: '2025-08-20T08:55:41.516Z'
      },
      {
        id: 2,
        sngine_email: 'admin@vottery.com',
        sngine_phone: '+8801700000001',
        first_name: 'Admin',
        last_name: 'Manager',
        user_type: 'individual_creator',
        admin_role: 'admin',
        subscription_status: 'subscribed',
        status: 'active',
        created_at: '2025-08-15T08:49:41.516Z',
        last_login: '2025-08-30T12:15:00.000Z',
        country: 'Bangladesh',
        city: 'Dhaka',
        user_age: 30,
        user_gender: 'Female',
        email_verified_at: '2025-08-15T08:50:41.516Z',
        phone_verified_at: '2025-08-15T08:52:41.516Z',
        biometric_registered_at: '2025-08-15T08:55:41.516Z'
      },
      {
        id: 3,
        sngine_email: 'moderator@vottery.com',
        sngine_phone: '+8801700000002',
        first_name: 'Sarah',
        last_name: 'Wilson',
        user_type: 'organization_creator',
        admin_role: 'moderator',
        subscription_status: 'subscribed',
        status: 'active',
        created_at: '2025-08-18T08:49:41.516Z',
        last_login: '2025-08-30T09:45:00.000Z',
        country: 'United States',
        city: 'New York',
        user_age: 28,
        user_gender: 'Female',
        email_verified_at: '2025-08-18T08:50:41.516Z',
        phone_verified_at: '2025-08-18T08:52:41.516Z',
        biometric_registered_at: '2025-08-18T08:55:41.516Z'
      },
      {
        id: 4,
        sngine_email: 'auditor@vottery.com',
        sngine_phone: '+8801700000003',
        first_name: 'John',
        last_name: 'Auditor',
        user_type: 'voter',
        admin_role: 'auditor',
        subscription_status: 'free',
        status: 'active',
        created_at: '2025-08-22T08:49:41.516Z',
        last_login: '2025-08-30T08:20:00.000Z',
        country: 'Canada',
        city: 'Toronto',
        user_age: 35,
        user_gender: 'Male',
        email_verified_at: '2025-08-22T08:50:41.516Z',
        phone_verified_at: '2025-08-22T08:52:41.516Z',
        biometric_registered_at: '2025-08-22T08:55:41.516Z'
      },
      {
        id: 5,
        sngine_email: 'editor@vottery.com',
        sngine_phone: '+8801700000004',
        first_name: 'Emma',
        last_name: 'Editor',
        user_type: 'individual_creator',
        admin_role: 'editor',
        subscription_status: 'subscribed',
        status: 'inactive',
        created_at: '2025-08-25T08:49:41.516Z',
        last_login: '2025-08-29T16:45:00.000Z',
        country: 'United Kingdom',
        city: 'London',
        user_age: 26,
        user_gender: 'Female',
        email_verified_at: '2025-08-25T08:50:41.516Z',
        phone_verified_at: '2025-08-25T08:52:41.516Z',
        biometric_registered_at: '2025-08-25T08:55:41.516Z'
      }
    ];
    setUsers(mockUsers);
  }, []);

  // Check admin access - only admin and manager can access this component
  if (!isAdmin()) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="bg-white rounded-lg shadow p-8 text-center max-w-md">
          <div className="mx-auto flex items-center justify-center h-12 w-12 rounded-full bg-red-100 mb-4">
            <svg className="h-6 w-6 text-red-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-5.218-8.364a9 9 0 1112.436 0L12 21l-5.218-8.364z" />
            </svg>
          </div>
          <h2 className="text-xl font-bold text-gray-900 mb-2">Access Denied</h2>
          <p className="text-gray-600 mb-4">You need admin or manager privileges to access this page.</p>
          <p className="text-sm text-gray-500">Current role: {userData?.admin_role || 'No role assigned'}</p>
          <div className="mt-4">
            <button 
              onClick={() => window.history.back()} 
              className="bg-gray-600 hover:bg-gray-700 text-white px-4 py-2 rounded-lg"
            >
              Go Back
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Admin role definitions based on milestone requirements
  const adminRoles = [
    { value: 'admin', label: 'Admin', description: 'Full system access and user management' },
    { value: 'manager', label: 'Manager', description: 'Management privileges and oversight' },
    { value: 'moderator', label: 'Moderator', description: 'Content moderation and user support' },
    { value: 'auditor', label: 'Auditor', description: 'Audit and compliance monitoring' },
    { value: 'editor', label: 'Editor', description: 'Content editing and review' },
    { value: 'advertiser', label: 'Advertiser', description: 'Advertisement management' },
    { value: 'analyst', label: 'Analyst', description: 'Data analysis and reporting only' }
  ];

  // User type definitions from milestone
  const userTypes = [
    { value: 'voter', label: 'Voter', description: 'Regular voting user' },
    { value: 'individual_creator', label: 'Individual Creator', description: 'Individual election creator' },
    { value: 'organization_creator', label: 'Organization Creator', description: 'Organization election creator' }
  ];

  // Subscription status options
  const subscriptionStatuses = [
    { value: 'free', label: 'Free', description: 'Limited access' },
    { value: 'subscribed', label: 'Subscribed', description: 'Unlimited access' }
  ];

  // Status options
  const statusOptions = [
    { value: 'active', label: 'Active' },
    { value: 'inactive', label: 'Inactive' },
    { value: 'suspended', label: 'Suspended' },
    { value: 'banned', label: 'Banned' }
  ];

  // Filter users based on search and filters
  const filteredUsers = users.filter(user => {
    const matchesSearch = user.sngine_email.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         `${user.first_name || ''} ${user.last_name || ''}`.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         user.sngine_phone.includes(searchTerm);
    const matchesRole = filterRole === 'all' || user.admin_role === filterRole;
    const matchesType = filterType === 'all' || user.user_type === filterType;
    
    return matchesSearch && matchesRole && matchesType;
  });

  // Handle role change
  const handleRoleChange = async (userId, newRole) => {
    try {
      setLoading(true);
      setUsers(users.map(user => 
        user.id === userId ? { ...user, admin_role: newRole } : user
      ));
      // Here you would make an API call to update the user role
      console.log(`Updating user ${userId} role to ${newRole}`);
      // Simulate API call
      await new Promise(resolve => setTimeout(resolve, 500));
    } catch (error) {
      setError('Failed to update user role');
    } finally {
      setLoading(false);
    }
  };

  // Handle user type change
  const handleTypeChange = async (userId, newType) => {
    try {
      setLoading(true);
      setUsers(users.map(user => 
        user.id === userId ? { ...user, user_type: newType } : user
      ));
      console.log(`Updating user ${userId} type to ${newType}`);
      await new Promise(resolve => setTimeout(resolve, 500));
    } catch (error) {
      setError('Failed to update user type');
    } finally {
      setLoading(false);
    }
  };

  // Handle status change
  const handleStatusChange = async (userId, newStatus) => {
    try {
      setLoading(true);
      setUsers(users.map(user => 
        user.id === userId ? { ...user, status: newStatus } : user
      ));
      console.log(`Updating user ${userId} status to ${newStatus}`);
      await new Promise(resolve => setTimeout(resolve, 500));
    } catch (error) {
      setError('Failed to update user status');
    } finally {
      setLoading(false);
    }
  };

  // Handle subscription change
  const handleSubscriptionChange = async (userId, newSubscription) => {
    try {
      setLoading(true);
      setUsers(users.map(user => 
        user.id === userId ? { ...user, subscription_status: newSubscription } : user
      ));
      console.log(`Updating user ${userId} subscription to ${newSubscription}`);
      await new Promise(resolve => setTimeout(resolve, 500));
    } catch (error) {
      setError('Failed to update subscription');
    } finally {
      setLoading(false);
    }
  };

  // Get role badge color
  const getRoleBadgeColor = (role) => {
    const colors = {
      admin: 'bg-red-100 text-red-800',
      manager: 'bg-purple-100 text-purple-800',
      moderator: 'bg-blue-100 text-blue-800',
      auditor: 'bg-yellow-100 text-yellow-800',
      editor: 'bg-green-100 text-green-800',
      advertiser: 'bg-indigo-100 text-indigo-800',
      analyst: 'bg-gray-100 text-gray-800'
    };
    return colors[role] || 'bg-gray-100 text-gray-800';
  };

  // Get status badge color
  const getStatusBadgeColor = (status) => {
    const colors = {
      active: 'bg-green-100 text-green-800',
      inactive: 'bg-yellow-100 text-yellow-800',
      suspended: 'bg-orange-100 text-orange-800',
      banned: 'bg-red-100 text-red-800'
    };
    return colors[status] || 'bg-gray-100 text-gray-800';
  };

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">User Management System</h1>
              <p className="text-gray-600">Milestone 1: Role-based user management and administration</p>
            </div>
            <div className="flex items-center space-x-3">
              <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-red-100 text-red-800">
                Admin: {userData?.admin_role}
              </span>
              <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-blue-100 text-blue-800">
                Total Users: {users.length}
              </span>
              <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-green-100 text-green-800">
                Filtered: {filteredUsers.length}
              </span>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Error Display */}
        {error && (
          <div className="mb-6 bg-red-50 border border-red-200 rounded-lg p-4">
            <div className="flex">
              <svg className="h-5 w-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <div className="ml-3">
                <p className="text-sm text-red-700">{error}</p>
              </div>
              <button
                onClick={() => setError(null)}
                className="ml-auto text-red-400 hover:text-red-600"
              >
                <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          </div>
        )}

        {/* Filters and Search */}
        <div className="bg-white rounded-lg shadow p-6 mb-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Search & Filter Users</h3>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Search Users</label>
              <input
                type="text"
                placeholder="Search by email, name, or phone..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Filter by Role</label>
              <select
                value={filterRole}
                onChange={(e) => setFilterRole(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="all">All Roles</option>
                {adminRoles.map(role => (
                  <option key={role.value} value={role.value}>{role.label}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Filter by Type</label>
              <select
                value={filterType}
                onChange={(e) => setFilterType(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                <option value="all">All Types</option>
                {userTypes.map(type => (
                  <option key={type.value} value={type.value}>{type.label}</option>
                ))}
              </select>
            </div>

            <div className="flex items-end">
              <button
                onClick={() => {
                  setSearchTerm('');
                  setFilterRole('all');
                  setFilterType('all');
                }}
                className="w-full px-4 py-2 bg-gray-100 hover:bg-gray-200 text-gray-700 rounded-lg transition duration-200"
              >
                Clear Filters
              </button>
            </div>
          </div>
        </div>

        {/* Users Management Table */}
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <div className="px-6 py-4 bg-gray-50 border-b">
            <h3 className="text-lg font-semibold text-gray-900">Users Management ({filteredUsers.length})</h3>
          </div>
          
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User Info</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Contact</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Admin Role</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User Type</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Subscription</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Verification</th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredUsers.map(user => (
                  <tr key={user.id} className="hover:bg-gray-50">
                    {/* User Info */}
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center">
                          <span className="text-sm font-medium text-blue-600">
                            {user.first_name?.[0] || user.sngine_email[0]?.toUpperCase()}
                            {user.last_name?.[0] || ''}
                          </span>
                        </div>
                        <div className="ml-3">
                          <div className="text-sm font-medium text-gray-900">
                            {user.first_name && user.last_name 
                              ? `${user.first_name} ${user.last_name}`
                              : 'Name not set'
                            }
                          </div>
                          <div className="text-sm text-gray-500">ID: {user.id}</div>
                        </div>
                      </div>
                    </td>
                    
                    {/* Contact */}
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-gray-900">{user.sngine_email}</div>
                      <div className="text-sm text-gray-500">{user.sngine_phone}</div>
                    </td>

                    {/* Admin Role */}
                    <td className="px-6 py-4 whitespace-nowrap">
                      <select
                        value={user.admin_role}
                        onChange={(e) => handleRoleChange(user.id, e.target.value)}
                        disabled={loading}
                        className="text-sm border border-gray-300 rounded px-2 py-1 focus:ring-2 focus:ring-blue-500"
                      >
                        {adminRoles.map(role => (
                          <option key={role.value} value={role.value}>{role.label}</option>
                        ))}
                      </select>
                      <div className={`mt-1 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getRoleBadgeColor(user.admin_role)}`}>
                        {user.admin_role}
                      </div>
                    </td>
                    
                    {/* User Type */}
                    <td className="px-6 py-4 whitespace-nowrap">
                      <select
                        value={user.user_type}
                        onChange={(e) => handleTypeChange(user.id, e.target.value)}
                        disabled={loading}
                        className="text-sm border border-gray-300 rounded px-2 py-1 focus:ring-2 focus:ring-blue-500"
                      >
                        {userTypes.map(type => (
                          <option key={type.value} value={type.value}>{type.label}</option>
                        ))}
                      </select>
                    </td>
                    
                    {/* Status */}
                    <td className="px-6 py-4 whitespace-nowrap">
                      <select
                        value={user.status}
                        onChange={(e) => handleStatusChange(user.id, e.target.value)}
                        disabled={loading}
                        className="text-sm border border-gray-300 rounded px-2 py-1 focus:ring-2 focus:ring-blue-500 mb-1"
                      >
                        {statusOptions.map(status => (
                          <option key={status.value} value={status.value}>{status.label}</option>
                        ))}
                      </select>
                      <div className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusBadgeColor(user.status)}`}>
                        {user.status}
                      </div>
                    </td>
                    
                    {/* Subscription */}
                    <td className="px-6 py-4 whitespace-nowrap">
                      <select
                        value={user.subscription_status}
                        onChange={(e) => handleSubscriptionChange(user.id, e.target.value)}
                        disabled={loading}
                        className="text-sm border border-gray-300 rounded px-2 py-1 focus:ring-2 focus:ring-blue-500 mb-1"
                      >
                        {subscriptionStatuses.map(sub => (
                          <option key={sub.value} value={sub.value}>{sub.label}</option>
                        ))}
                      </select>
                      <div className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                        user.subscription_status === 'subscribed' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                      }`}>
                        {user.subscription_status}
                      </div>
                    </td>

                    {/* Verification Status */}
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="space-y-1">
                        <div className="flex items-center text-xs">
                          <span className={`w-2 h-2 rounded-full mr-1 ${user.email_verified_at ? 'bg-green-500' : 'bg-red-500'}`}></span>
                          Email
                        </div>
                        <div className="flex items-center text-xs">
                          <span className={`w-2 h-2 rounded-full mr-1 ${user.phone_verified_at ? 'bg-green-500' : 'bg-red-500'}`}></span>
                          Phone
                        </div>
                        <div className="flex items-center text-xs">
                          <span className={`w-2 h-2 rounded-full mr-1 ${user.biometric_registered_at ? 'bg-green-500' : 'bg-red-500'}`}></span>
                          Biometric
                        </div>
                      </div>
                    </td>
                    
                    {/* Actions */}
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium space-y-1">
                      <button
                        onClick={() => {
                          setSelectedUser(user);
                          setShowUserModal(true);
                        }}
                        className="text-blue-600 hover:text-blue-900 block"
                      >
                        View Details
                      </button>
                      <button className="text-green-600 hover:text-green-900 block">
                        Edit Profile
                      </button>
                      <button className="text-red-600 hover:text-red-900 block">
                        Reset Password
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          
          {filteredUsers.length === 0 && (
            <div className="px-6 py-12 text-center">
              <div className="text-gray-400 mb-2">
                <svg className="mx-auto h-12 w-12" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197m13.5-9a2.5 2.5 0 11-5 0 2.5 2.5 0 015 0z" />
                </svg>
              </div>
              <p className="text-gray-500 text-lg">No users found</p>
              <p className="text-gray-400 text-sm">Try adjusting your search criteria</p>
            </div>
          )}
        </div>

        {/* Statistics Cards */}
        <div className="mt-8 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {/* Admin Roles Statistics */}
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Admin Roles</h3>
            <div className="space-y-3">
              {adminRoles.map(role => (
                <div key={role.value} className="flex justify-between items-center">
                  <div>
                    <div className="font-medium text-sm text-gray-900">{role.label}</div>
                    <div className="text-xs text-gray-500">{role.description}</div>
                  </div>
                  <span className={`text-xs px-2 py-1 rounded-full ${getRoleBadgeColor(role.value)}`}>
                    {users.filter(u => u.admin_role === role.value).length}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* User Types Statistics */}
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">User Types</h3>
            <div className="space-y-3">
              {userTypes.map(type => (
                <div key={type.value} className="flex justify-between items-center">
                  <div>
                    <div className="font-medium text-sm text-gray-900">{type.label}</div>
                    <div className="text-xs text-gray-500">{type.description}</div>
                  </div>
                  <span className="text-xs bg-blue-100 text-blue-800 px-2 py-1 rounded-full">
                    {users.filter(u => u.user_type === type.value).length}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Subscription Statistics */}
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Subscriptions</h3>
            <div className="space-y-3">
              {subscriptionStatuses.map(sub => (
                <div key={sub.value} className="flex justify-between items-center">
                  <div>
                    <div className="font-medium text-sm text-gray-900">{sub.label}</div>
                    <div className="text-xs text-gray-500">{sub.description}</div>
                  </div>
                  <span className={`text-xs px-2 py-1 rounded-full ${
                    sub.value === 'subscribed' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                  }`}>
                    {users.filter(u => u.subscription_status === sub.value).length}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* System Statistics */}
          <div className="bg-white rounded-lg shadow p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">System Overview</h3>
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Total Users</span>
                <span className="font-medium text-blue-600">{users.length}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Active Users</span>
                <span className="font-medium text-green-600">{users.filter(u => u.status === 'active').length}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Verified Users</span>
                <span className="font-medium text-purple-600">
                  {users.filter(u => u.email_verified_at && u.phone_verified_at && u.biometric_registered_at).length}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Subscribed Users</span>
                <span className="font-medium text-orange-600">{users.filter(u => u.subscription_status === 'subscribed').length}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm text-gray-600">Admin Users</span>
                <span className="font-medium text-red-600">{users.filter(u => u.admin_role === 'admin').length}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Milestone 1 Security Features Demonstration */}
        <div className="mt-8 bg-gradient-to-r from-blue-600 to-purple-600 rounded-lg p-6 text-white">
          <h3 className="text-xl font-bold mb-4">Milestone 1: Implemented Security Features</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div className="bg-white bg-opacity-20 rounded-lg p-4">
              <div className="flex items-center mb-2">
                <svg className="w-6 h-6 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
                <h4 className="font-semibold">End-to-End Encryption</h4>
              </div>
              <ul className="text-sm space-y-1 opacity-90">
                <li>• RSA/ElGamal Implementation</li>
                <li>• Cryptographic Key Management</li>
                <li>• Threshold Decryption System</li>
              </ul>
            </div>
            
            <div className="bg-white bg-opacity-20 rounded-lg p-4">
              <div className="flex items-center mb-2">
                <svg className="w-6 h-6 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                <h4 className="font-semibold">Digital Signatures</h4>
              </div>
              <ul className="text-sm space-y-1 opacity-90">
                <li>• SHA-256 Signature Generation</li>
                <li>• Digital Signature Verification</li>
                <li>• Tamper-Evident Logging</li>
              </ul>
            </div>

            <div className="bg-white bg-opacity-20 rounded-lg p-4">
              <div className="flex items-center mb-2">
                <svg className="w-6 h-6 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
                <h4 className="font-semibold">HTTPS & Security</h4>
              </div>
              <ul className="text-sm space-y-1 opacity-90">
                <li>• SSL Certificate Handling</li>
                <li>• HTTPS Enforcement</li>
                <li>• OWASP Security Compliance</li>
              </ul>
            </div>

            <div className="bg-white bg-opacity-20 rounded-lg p-4">
              <div className="flex items-center mb-2">
                <svg className="w-6 h-6 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 100 4m0-4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 100 4m0-4v2m0-6V4" />
                </svg>
                <h4 className="font-semibold">Input Validation</h4>
              </div>
              <ul className="text-sm space-y-1 opacity-90">
                <li>• Email/Phone Sanitization</li>
                <li>• XSS Prevention</li>
                <li>• SQL Injection Protection</li>
              </ul>
            </div>

            <div className="bg-white bg-opacity-20 rounded-lg p-4">
              <div className="flex items-center mb-2">
                <svg className="w-6 h-6 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.031 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
                <h4 className="font-semibold">Rate Limiting</h4>
              </div>
              <ul className="text-sm space-y-1 opacity-90">
                <li>• DDoS Protection</li>
                <li>• API Rate Limiting</li>
                <li>• Brute Force Prevention</li>
              </ul>
            </div>

            <div className="bg-white bg-opacity-20 rounded-lg p-4">
              <div className="flex items-center mb-2">
                <svg className="w-6 h-6 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                </svg>
                <h4 className="font-semibold">Token Management</h4>
              </div>
              <ul className="text-sm space-y-1 opacity-90">
                <li>• Access Token Rotation</li>
                <li>• Refresh Token Rotation</li>
                <li>• JWT Security</li>
              </ul>
            </div>
          </div>
        </div>
      </div>

      {/* User Details Modal */}
      {showUserModal && selectedUser && (
        <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
          <div className="relative top-20 mx-auto p-5 border max-w-2xl shadow-lg rounded-md bg-white">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-xl font-semibold text-gray-900">User Details - {selectedUser.sngine_email}</h3>
              <button
                onClick={() => setShowUserModal(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Basic Information */}
              <div className="space-y-4">
                <div>
                  <h4 className="font-medium text-gray-900 mb-3">Basic Information</h4>
                  <div className="space-y-3">
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Full Name</label>
                      <div className="mt-1 text-sm text-gray-900">
                        {selectedUser.first_name && selectedUser.last_name 
                          ? `${selectedUser.first_name} ${selectedUser.last_name}`
                          : 'Not set'
                        }
                      </div>
                    </div>
                    
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Email</label>
                      <div className="mt-1 text-sm text-gray-900">{selectedUser.sngine_email}</div>
                    </div>
                    
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Phone</label>
                      <div className="mt-1 text-sm text-gray-900">{selectedUser.sngine_phone}</div>
                    </div>
                    
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Location</label>
                      <div className="mt-1 text-sm text-gray-900">
                        {selectedUser.city && selectedUser.country 
                          ? `${selectedUser.city}, ${selectedUser.country}`
                          : 'Not specified'
                        }
                      </div>
                    </div>
                  </div>
                </div>

                {/* Demographics */}
                <div>
                  <h4 className="font-medium text-gray-900 mb-3">Demographics</h4>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Age</label>
                      <div className="mt-1 text-sm text-gray-900">{selectedUser.user_age || 'Not set'}</div>
                    </div>
                    
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Gender</label>
                      <div className="mt-1 text-sm text-gray-900">{selectedUser.user_gender || 'Not set'}</div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Account Information */}
              <div className="space-y-4">
                <div>
                  <h4 className="font-medium text-gray-900 mb-3">Account Information</h4>
                  <div className="space-y-3">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700">User Type</label>
                        <span className="mt-1 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                          {selectedUser.user_type.replace('_', ' ')}
                        </span>
                      </div>
                      
                      <div>
                        <label className="block text-sm font-medium text-gray-700">Admin Role</label>
                        <span className={`mt-1 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getRoleBadgeColor(selectedUser.admin_role)}`}>
                          {selectedUser.admin_role}
                        </span>
                      </div>
                    </div>
                    
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700">Status</label>
                        <span className={`mt-1 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusBadgeColor(selectedUser.status)}`}>
                          {selectedUser.status}
                        </span>
                      </div>
                      
                      <div>
                        <label className="block text-sm font-medium text-gray-700">Subscription</label>
                        <span className={`mt-1 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                          selectedUser.subscription_status === 'subscribed' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                        }`}>
                          {selectedUser.subscription_status}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Verification Status */}
                <div>
                  <h4 className="font-medium text-gray-900 mb-3">Verification Status</h4>
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Email Verification</span>
                      <div className="flex items-center">
                        <span className={`w-2 h-2 rounded-full mr-2 ${selectedUser.email_verified_at ? 'bg-green-500' : 'bg-red-500'}`}></span>
                        <span className="text-sm">
                          {selectedUser.email_verified_at ? 'Verified' : 'Not Verified'}
                        </span>
                      </div>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Phone Verification</span>
                      <div className="flex items-center">
                        <span className={`w-2 h-2 rounded-full mr-2 ${selectedUser.phone_verified_at ? 'bg-green-500' : 'bg-red-500'}`}></span>
                        <span className="text-sm">
                          {selectedUser.phone_verified_at ? 'Verified' : 'Not Verified'}
                        </span>
                      </div>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-gray-600">Biometric Registration</span>
                      <div className="flex items-center">
                        <span className={`w-2 h-2 rounded-full mr-2 ${selectedUser.biometric_registered_at ? 'bg-green-500' : 'bg-red-500'}`}></span>
                        <span className="text-sm">
                          {selectedUser.biometric_registered_at ? 'Registered' : 'Not Registered'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Timestamps */}
                <div>
                  <h4 className="font-medium text-gray-900 mb-3">Timeline</h4>
                  <div className="space-y-2">
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Joined</label>
                      <div className="mt-1 text-sm text-gray-900">
                        {new Date(selectedUser.created_at).toLocaleDateString('en-US', {
                          year: 'numeric',
                          month: 'long',
                          day: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit'
                        })}
                      </div>
                    </div>
                    
                    <div>
                      <label className="block text-sm font-medium text-gray-700">Last Login</label>
                      <div className="mt-1 text-sm text-gray-900">
                        {selectedUser.last_login ? new Date(selectedUser.last_login).toLocaleDateString('en-US', {
                          year: 'numeric',
                          month: 'long',
                          day: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit'
                        }) : 'Never'}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
            
            <div className="flex justify-end mt-6 space-x-3">
              <button
                onClick={() => setShowUserModal(false)}
                className="px-4 py-2 text-gray-600 bg-gray-100 rounded-lg hover:bg-gray-200 transition duration-200"
              >
                Close
              </button>
              <button className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition duration-200">
                Edit User
              </button>
              <button className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition duration-200">
                Send Message
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AdminManagement;