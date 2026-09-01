declare module '*.css';
declare module '*.scss';
declare module '*.sass';
declare module '*.less';

interface ImportMetaEnv {
	readonly VITE_API_URL?: string
	readonly VITE_SOCKET_URL?: string
	readonly VITE_DEMO_MODE?: string
}

interface ImportMeta {
	readonly env: ImportMetaEnv
}
