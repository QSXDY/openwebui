<script lang="ts">
	import { getContext, onMount } from 'svelte';
	import { toast } from 'svelte-sonner';
	import Spinner from '$lib/components/common/Spinner.svelte';
	import { generateInitialsImage } from '$lib/utils';
	import {
		getWeChatQRCode,
		weChatFollowLogin,
		checkWeChatFollowStatus,
		bindPhoneNumber,
		updateUserProfiles
	} from '$lib/apis/auths';
	import { user } from '$lib/stores';
	const i18n = getContext('i18n');
	let logintetxt = false;
	let show = false;
	let name = '';
	let profileImageUrl = '';
	let newPasswordConfirm = '';
	// 微信公众号关注登录相关变量
	let wechatQRCode = '';
	let wechatSceneId = '';
	let wechatPolling = false;
	let wechatPollingInterval = null;
	let qrCodeExpired = false;

	// 刷新微信二维码
	const refreshWeChatQR = () => {
		stopWeChatPolling();
		getWeChatQR();
	};
	$: if (show === true) {
		// getWeChatQR();
	}

	// 当切换到其他登录方式时停止微信轮询
	$: if (show !== true) {
		// stopWeChatPolling();
	}
	function isWeChatBrowser() {
		const userAgent = navigator.userAgent || navigator.vendor || window.opera;
		// 匹配"MicroMessenger"关键词（不区分大小写）
		return /MicroMessenger/i.test(userAgent);
	}
	onMount(async () => {
		console.log('onMount', $user);
		name = $user?.name;
		profileImageUrl = $user?.profile_image_url;
		if (isWeChatBrowser()) {
			logintetxt = true;
		} else {
			logintetxt = false;
		}
	});
	// 获取微信公众号关注二维码
	const getWeChatQR = async () => {
		try {
			const response = await getWeChatQRCode();
			if (response) {
				wechatQRCode = response.qr_code;
				wechatSceneId = response.scene_id;
				qrCodeExpired = false;
				startWeChatPolling();

				// 设置二维码过期时间
				setTimeout(() => {
					if (!qrCodeExpired) {
						qrCodeExpired = true;
						stopWeChatPolling();
					}
				}, response.expires_in * 1000);
			}
		} catch (error) {
			console.error('微信公众号二维码获取失败:', error);
			toast.error(`获取微信二维码失败: ${error}`);
		}
	};
	// 开始轮询微信关注状态
	const startWeChatPolling = () => {
		if (wechatPolling) return;

		wechatPolling = true;
		wechatPollingInterval = setInterval(async () => {
			try {
				const response = await checkWeChatFollowStatus(wechatSceneId);
				if (response && response.status === 'followed' && response.openid) {
					stopWeChatPolling();
					if (name !== $user?.name) {
						if (profileImageUrl === generateInitialsImage($user?.name) || profileImageUrl === '') {
							profileImageUrl = generateInitialsImage(name);
						}
					}
					const updatedUser = await updateUserProfiles(
						localStorage.token,
						response.openid,
						wechatSceneId
					).catch((error) => {
						toast.error(`${error}`);
						stopWeChatPolling();
					});
					show = false;
					console.log('updatedUser', updatedUser);
					// 处理关注成功，进行登录
				} else if (response && response.status === 'expired') {
					stopWeChatPolling();
					qrCodeExpired = true;
				} else if (response && response.status === 'not_found') {
					stopWeChatPolling();
					toast.error('登录状态已失效，请重新获取二维码');
					qrCodeExpired = true;
				}
			} catch (error) {
				console.error('微信关注状态检查失败:', error);
				// 检查失败不停止轮询，除非是严重错误
				if (error.toString().includes('not_found')) {
					stopWeChatPolling();
					qrCodeExpired = true;
				}
			}
		}, 2000); // 每2秒检查一次
	};
	// 停止轮询
	const stopWeChatPolling = () => {
		if (wechatPollingInterval) {
			clearInterval(wechatPollingInterval);
			wechatPollingInterval = null;
		}
		wechatPolling = false;
	};
</script>

<div
	class="flex flex-col text-sm"
	on:submit|preventDefault={() => {
		updatePasswordHandler();
	}}
>
	<div class="flex justify-between items-center text-sm">
		<div class="  font-medium">微信绑定</div>
		<button class=" text-xs font-medium text-gray-500" type="button"
			>{$user.wechat_openid == null ? '未绑定' : '已绑定'}</button
		>
	</div>
	<hr class="border-gray-50 dark:border-gray-850 my-2" />
	<div class="flex justify-between items-center text-sm">
		<div class="  font-medium">手机号绑定</div>
		<button class=" text-xs font-medium text-gray-500" type="button"
			>{$user.phone_number == null ? '未绑定' : $user.phone_number}</button
		>
	</div>
	{#if show}
		<div class="flex flex-col mt-4 items-center">
			{#if wechatQRCode && !qrCodeExpired}
				<div
					class="bg-white p-1 rounded-lg shadow-md border-1 border-gray-200 dark:border-gray-600"
				>
					<img src={wechatQRCode} alt="微信登录二维码" class="w-48 h-48" />
				</div>

				{#if wechatPolling}
					<div class="flex items-center mt-4 text-sm text-gray-600 dark:text-gray-400">
						<Spinner class="w-4 h-4 mr-2" />
						<span class="animate-pulse">等待关注公众号中...</span>
					</div>
				{/if}
			{:else if qrCodeExpired}
				<div class="text-center">
					<div
						class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 mb-4"
					>
						<div class="text-red-600 dark:text-red-400 text-sm font-medium">⚠️ 二维码已过期</div>
						<div class="text-red-500 dark:text-red-300 text-xs mt-1">
							请点击下方按钮重新获取二维码
						</div>
					</div>
					<button
						on:click={refreshWeChatQR}
						class="bg-green-500 hover:bg-green-600 text-white transition rounded-full font-medium text-sm py-2 px-6 shadow-md hover:shadow-lg"
					>
						🔄 刷新二维码
					</button>
				</div>
			{:else}
				<div class="flex flex-col items-center">
					<div
						class="bg-gray-100 dark:bg-gray-800 rounded-lg p-8 mb-4 w-48 h-48 flex items-center justify-center"
					>
						<div class="text-center">
							<Spinner class="w-8 h-8 mx-auto mb-2" />
							<div class="text-sm text-gray-600 dark:text-gray-400">正在生成二维码...</div>
						</div>
					</div>
				</div>
			{/if}

			<div
				class="mt-4 text-xs text-gray-500 dark:text-gray-400 text-center max-w-xs leading-relaxed"
			>
				💡 请{logintetxt ? '长按' : '使用微信扫描上方'}二维码关注公众号，关注成功后即可自动绑定
			</div>

			{#if wechatPolling}
				<div class="mt-2 text-xs text-blue-600 dark:text-blue-400 text-center">
					二维码有效期：10分钟
				</div>
			{/if}
		</div>
	{/if}
</div>
