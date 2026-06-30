import { FormEvent, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { authApi, type ManagedUser } from '@/api/client';
import { Header } from '@/components/Layout/Header';

const fallbackRoles = ['viewer', 'analyst', 'threat_intel', 'detection_engineer', 'incident_responder', 'auditor', 'security_admin', 'service_account', 'admin'];
const fallbackPermissions = ['read', 'run_analysis', 'manage_intel', 'manage_detections', 'run_attack_simulation', 'manage_feeds', 'forward_siem', 'upload_files', 'export_data', 'manage_users', 'manage_auth', 'view_audit'];

function fmt(value: string | null) {
  return value ? new Date(value).toLocaleString() : '-';
}

function TogglePermission({ value, selected, onChange }: { value: string; selected: boolean; onChange: (next: boolean) => void }) {
  return (
    <label className={`flex cursor-pointer items-center gap-2 rounded border px-2 py-1 text-xs ${selected ? 'border-mitre-accent bg-mitre-accent/10 text-white' : 'border-gray-700 bg-gray-950 text-gray-400'}`}>
      <input type="checkbox" checked={selected} onChange={event => onChange(event.target.checked)} />
      {value}
    </label>
  );
}

export function AdminUsers() {
  const qc = useQueryClient();
  const { data: status } = useQuery({ queryKey: ['auth-status-admin'], queryFn: authApi.status });
  const { data: users = [] } = useQuery({ queryKey: ['admin-users'], queryFn: authApi.users });
  const { data: sessions = [] } = useQuery({ queryKey: ['admin-sessions'], queryFn: authApi.sessions });
  const { data: audit = [] } = useQuery({ queryKey: ['auth-audit'], queryFn: authApi.audit });

  const roles = status?.roles?.length ? status.roles : fallbackRoles;
  const permissions = status?.permissions?.length ? status.permissions : fallbackPermissions;
  const policy = status?.password_policy;
  const minPasswordLength = policy?.min_length ?? 12;

  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('viewer');
  const [extraPermissions, setExtraPermissions] = useState<string[]>([]);
  const [enabled, setEnabled] = useState(true);
  const [passwordTarget, setPasswordTarget] = useState<ManagedUser | null>(null);
  const [newPassword, setNewPassword] = useState('');

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ['admin-users'] });
    qc.invalidateQueries({ queryKey: ['admin-sessions'] });
    qc.invalidateQueries({ queryKey: ['auth-audit'] });
  };
  const createUser = useMutation({ mutationFn: authApi.createUser, onSuccess: () => { setUsername(''); setDisplayName(''); setPassword(''); setRole('viewer'); setExtraPermissions([]); setEnabled(true); refresh(); } });
  const updateUser = useMutation({ mutationFn: ({ id, body }: { id: string; body: { display_name?: string; role?: string; permissions?: string[]; enabled?: boolean } }) => authApi.updateUser(id, body), onSuccess: refresh });
  const resetPassword = useMutation({ mutationFn: ({ id, password }: { id: string; password: string }) => authApi.setPassword(id, password), onSuccess: () => { setPasswordTarget(null); setNewPassword(''); refresh(); } });
  const revokeSessions = useMutation({ mutationFn: authApi.revokeUserSessions, onSuccess: refresh });
  const disableMfa = useMutation({ mutationFn: authApi.disableMfa, onSuccess: refresh });

  const activeSessionCount = useMemo(() => sessions.filter(item => item.active).length, [sessions]);

  function submit(event: FormEvent) {
    event.preventDefault();
    createUser.mutate({ username, display_name: displayName, password, role, permissions: extraPermissions, enabled });
  }

  function updatePermissions(user: ManagedUser, permission: string, selected: boolean) {
    const current = new Set(user.permissions || []);
    if (selected) current.add(permission); else current.delete(permission);
    updateUser.mutate({ id: user.id, body: { permissions: [...current].sort() } });
  }

  return (
    <>
      <Header title="Admin Panel" />
      <div className="flex-1 overflow-y-auto p-6">
        <div className="mx-auto grid max-w-7xl gap-6">
          <section className="grid gap-4 md:grid-cols-4">
            <Metric label="Users" value={String(users.length)} />
            <Metric label="Active sessions" value={String(activeSessionCount)} />
            <Metric label="SSO mode" value={status?.sso_mode || 'proxy'} />
            <Metric label="Password minimum" value={`${minPasswordLength} chars`} />
          </section>

          <section className="grid gap-6 xl:grid-cols-[420px_1fr]">
            <div className="rounded border border-gray-700 bg-gray-900">
              <div className="border-b border-gray-700 p-4">
                <h2 className="font-semibold text-white">Create user</h2>
                <p className="mt-1 text-xs text-gray-500">Use named accounts. Extra permissions extend the selected role.</p>
              </div>
              <form onSubmit={submit} className="space-y-4 p-4">
                <label className="block"><span className="label">Username</span><input className="field" value={username} onChange={event => setUsername(event.target.value)} /></label>
                <label className="block"><span className="label">Display name</span><input className="field" value={displayName} onChange={event => setDisplayName(event.target.value)} /></label>
                <label className="block"><span className="label">Initial password</span><input className="field" type="password" value={password} onChange={event => setPassword(event.target.value)} /></label>
                <label className="block"><span className="label">Role</span><select className="field" value={role} onChange={event => setRole(event.target.value)}>{roles.map(item => <option key={item}>{item}</option>)}</select></label>
                <div>
                  <span className="label">Extra permissions</span>
                  <div className="mt-2 grid max-h-52 gap-2 overflow-y-auto pr-1">
                    {permissions.map(item => (
                      <TogglePermission key={item} value={item} selected={extraPermissions.includes(item)} onChange={next => setExtraPermissions(prev => next ? [...new Set([...prev, item])].sort() : prev.filter(p => p !== item))} />
                    ))}
                  </div>
                </div>
                <label className="flex items-center gap-2 text-sm text-gray-300"><input type="checkbox" checked={enabled} onChange={event => setEnabled(event.target.checked)} /> Enabled</label>
                {createUser.error && <div className="rounded border border-red-500/40 bg-red-950/30 p-3 text-xs text-red-200">{createUser.error.message}</div>}
                <button className="primary w-full" disabled={createUser.isPending || !username || password.length < minPasswordLength}>Create user</button>
              </form>
            </div>

            <div className="rounded border border-gray-700 bg-gray-900">
              <div className="border-b border-gray-700 p-4">
                <h2 className="font-semibold text-white">Users and permissions</h2>
                <p className="mt-1 text-xs text-gray-500">Roles are coarse defaults. Effective permissions are role permissions plus explicit grants.</p>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full min-w-[980px] text-left text-sm">
                  <thead className="bg-gray-950 text-xs uppercase text-gray-500">
                    <tr><th className="p-3">User</th><th className="p-3">Role</th><th className="p-3">Permissions</th><th className="p-3">Security</th><th className="p-3">Last login</th><th className="p-3 text-right">Actions</th></tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800">
                    {users.map(user => (
                      <tr key={user.id}>
                        <td className="p-3 align-top"><div className="font-semibold text-white">{user.username}</div><div className="text-xs text-gray-500">{user.display_name || '-'}</div><div className="mt-1 text-[10px] text-gray-600">{user.auth_provider}</div></td>
                        <td className="p-3 align-top"><select className="field min-w-44" value={user.role} onChange={event => updateUser.mutate({ id: user.id, body: { role: event.target.value } })}>{roles.map(item => <option key={item}>{item}</option>)}</select></td>
                        <td className="p-3 align-top">
                          <div className="grid max-h-40 min-w-72 gap-1 overflow-y-auto pr-1">
                            {permissions.map(item => <TogglePermission key={item} value={item} selected={(user.permissions || []).includes(item)} onChange={next => updatePermissions(user, item, next)} />)}
                          </div>
                        </td>
                        <td className="p-3 align-top text-xs">
                          <button className={user.enabled ? 'secondary-action border-green-700 text-green-300' : 'secondary-action border-red-700 text-red-300'} onClick={() => updateUser.mutate({ id: user.id, body: { enabled: !user.enabled } })}>{user.enabled ? 'Enabled' : 'Disabled'}</button>
                          <div className="mt-2 text-gray-500">MFA: {user.mfa_enabled ? 'enabled' : 'off'}</div>
                        </td>
                        <td className="p-3 align-top text-xs text-gray-500">{fmt(user.last_login_at)}</td>
                        <td className="space-y-2 p-3 text-right align-top">
                          <button className="secondary-action" onClick={() => setPasswordTarget(user)}>Reset password</button>
                          <button className="secondary-action" onClick={() => revokeSessions.mutate(user.id)}>Revoke sessions</button>
                          {user.mfa_enabled && <button className="secondary-action border-amber-700 text-amber-200" onClick={() => disableMfa.mutate(user.id)}>Disable MFA</button>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </section>

          <section className="grid gap-6 xl:grid-cols-2">
            <Panel title="Recent sessions">
              <table className="w-full text-left text-xs">
                <thead className="text-gray-500"><tr><th className="py-2">User</th><th>IP</th><th>Status</th><th>Expires</th></tr></thead>
                <tbody className="divide-y divide-gray-800">
                  {sessions.slice(0, 20).map(item => <tr key={item.id}><td className="py-2 text-white">{item.username}</td><td>{item.ip_address || '-'}</td><td className={item.active ? 'text-green-300' : 'text-gray-500'}>{item.active ? 'active' : 'closed'}</td><td>{fmt(item.expires_at)}</td></tr>)}
                </tbody>
              </table>
            </Panel>
            <Panel title="Auth audit trail">
              <table className="w-full text-left text-xs">
                <thead className="text-gray-500"><tr><th className="py-2">Time</th><th>Actor</th><th>Action</th><th>Object</th></tr></thead>
                <tbody className="divide-y divide-gray-800">
                  {audit.slice(0, 20).map(item => <tr key={item.id}><td className="py-2">{fmt(item.created_at)}</td><td className="text-white">{item.actor}</td><td className="text-mitre-accent">{item.action}</td><td>{item.object_type}</td></tr>)}
                </tbody>
              </table>
            </Panel>
          </section>
        </div>
      </div>
      {passwordTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-6" onClick={() => setPasswordTarget(null)}>
          <form className="w-full max-w-md rounded border border-gray-700 bg-gray-900 p-5" onClick={event => event.stopPropagation()} onSubmit={event => { event.preventDefault(); resetPassword.mutate({ id: passwordTarget.id, password: newPassword }); }}>
            <h3 className="font-semibold text-white">Reset password for {passwordTarget.username}</h3>
            <label className="mt-4 block"><span className="label">New password</span><input className="field" type="password" value={newPassword} onChange={event => setNewPassword(event.target.value)} autoFocus /></label>
            {resetPassword.error && <div className="mt-3 rounded border border-red-500/40 bg-red-950/30 p-3 text-xs text-red-200">{resetPassword.error.message}</div>}
            <div className="mt-4 flex justify-end gap-2"><button type="button" className="secondary-action" onClick={() => setPasswordTarget(null)}>Cancel</button><button className="primary-action" disabled={newPassword.length < minPasswordLength}>Save password</button></div>
          </form>
        </div>
      )}
    </>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div className="rounded border border-gray-700 bg-gray-900 p-4"><div className="text-2xl font-bold text-white">{value}</div><div className="mt-1 text-xs text-gray-500">{label}</div></div>;
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return <div className="rounded border border-gray-700 bg-gray-900"><div className="border-b border-gray-700 p-4"><h2 className="font-semibold text-white">{title}</h2></div><div className="max-h-96 overflow-auto p-4">{children}</div></div>;
}
