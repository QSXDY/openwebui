<script>
	import { toast } from 'svelte-sonner';

	import { onMount, onDestroy, getContext, tick } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';

	import { getBackendConfig } from '$lib/apis';
	import {
		ldapUserSignIn,
		getSessionUser,
		userSignIn,
		userSignUp,
		smsSendsend,
		getWeChatQRCode,
		weChatFollowLogin,
		checkWeChatFollowStatus,
		bindPhoneNumber,
		bindWeChat
	} from '$lib/apis/auths';

	import { WEBUI_API_BASE_URL, WEBUI_BASE_URL } from '$lib/constants';
	import { WEBUI_NAME, config, user, socket } from '$lib/stores';

	import { generateInitialsImage, canvasPixelTest } from '$lib/utils';

	import Spinner from '$lib/components/common/Spinner.svelte';
	import OnBoarding from '$lib/components/OnBoarding.svelte';

	const i18n = getContext('i18n');

	let loaded = false;

	let mode = $config?.features.enable_ldap ? 'ldap' : 'signin';

	let name = '';
	let email = '';
	let phone = '';
	let phonecode = '';
	let password = '';
	let login = 'email';
	let ldapUsername = '';
	let codetext = '发送验证码';
	let isCounting = false;
	let countdown = 60;

	// 微信公众号关注登录相关变量
	let wechatQRCode = '';
	let wechatSceneId = '';
	let wechatPolling = false;
	let wechatPollingInterval = null;
	let qrCodeExpired = false;
	let needBindPhone = false;  // 是否需要绑定手机号
	let showBindPhoneModal = false;  // 显示绑定手机号弹窗
	const querystringValue = (key) => {
		const querystring = window.location.search;
		const urlParams = new URLSearchParams(querystring);
		return urlParams.get(key);
	};

	const setSessionUser = async (sessionUser) => {
		if (sessionUser) {
			console.log(sessionUser);
			
			// 检查是否需要绑定手机号
			if (sessionUser.need_bind_phone) {
				needBindPhone = true;
				showBindPhoneModal = true;
				toast.info('登录成功，请绑定手机号以完善账户信息');
			} else {
				toast.success($i18n.t(`You're now logged in.`));
			}
			
			if (sessionUser.token) {
				localStorage.token = sessionUser.token;
			}
			$socket.emit('user-join', { auth: { token: sessionUser.token } });
			await user.set(sessionUser);
			await config.set(await getBackendConfig());

			// 如果不需要绑定手机号，直接跳转
			if (!sessionUser.need_bind_phone) {
				const redirectPath = querystringValue('redirect') || '/';
				goto(redirectPath);
			}
		}
	};

	const signInHandler = async () => {
		const sessionUser = await userSignIn(email, password).catch((error) => {
			toast.error(`${error}`);
			return null;
		});

		await setSessionUser(sessionUser);
	};

	const signUpHandler = async () => {
		const sessionUser = await userSignUp(name, email, password, generateInitialsImage(name)).catch(
			(error) => {
				toast.error(`${error}`);
				return null;
			}
		);

		await setSessionUser(sessionUser);
	};

	const phoneUpHandler = async () => {
		const sessionUser = await userSignUp(name, email, password, generateInitialsImage(name)).catch(
			(error) => {
				toast.error(`${error}`);
				return null;
			}
		);

		await setSessionUser(sessionUser);
	};

	const ldapSignInHandler = async () => {
		const sessionUser = await ldapUserSignIn(ldapUsername, password).catch((error) => {
			toast.error(`${error}`);
			return null;
		});
		await setSessionUser(sessionUser);
	};

	const submitHandler = async () => {
		if (mode === 'ldap') {
			await ldapSignInHandler();
		} else if (mode === 'signin') {
			if (login === 'email') {
				await signInHandler();
			} else {
				return toast.error(`目前处于内部测试阶段，暂时无法使用。`);
				console.log('手机号登录ldap');
			}
		} else {
			if (login === 'email') {
				await signUpHandler();
			} else {
				return toast.error(`目前处于内部测试阶段，暂时无法使用。`);
				await phoneUpHandler();
			}
		}
	};

	const checkOauthCallback = async () => {
		if (!$page.url.hash) {
			return;
		}
		const hash = $page.url.hash.substring(1);
		if (!hash) {
			return;
		}
		const params = new URLSearchParams(hash);
		const token = params.get('token');
		if (!token) {
			return;
		}
		const sessionUser = await getSessionUser(token).catch((error) => {
			toast.error(`${error}`);
			return null;
		});
		if (!sessionUser) {
			return;
		}
		localStorage.token = token;
		await setSessionUser(sessionUser);
	};

	let onboarding = false;

	async function setLogoImage() {
		await tick();
		const logo = document.getElementById('logo');

		if (logo) {
			const isDarkMode = document.documentElement.classList.contains('dark');

			if (isDarkMode) {
				const darkImage = new Image();
				darkImage.src = '/static/favicon-dark.png';

				darkImage.onload = () => {
					logo.src = '/static/favicon-dark.png';
					logo.style.filter = ''; // Ensure no inversion is applied if favicon-dark.png exists
				};

				darkImage.onerror = () => {
					logo.style.filter = 'invert(1)'; // Invert image if favicon-dark.png is missing
				};
			}
		}
	}

	async function sendCode() {
		console.log('sendCode发送验证码', phone);
		
		// 确定验证码类型
		let codeType = 'register';
		if (showBindPhoneModal) {
			codeType = 'bind';
		} else if (mode === 'signin') {
			codeType = 'login';
		}
		
		try {
			const sessionUser = await smsSendsend(phone, codeType);
			if (sessionUser.success) {
				toast.success(`验证码发送成功，请注意查收。`);
				isCounting = true;
				codetext = '已发送';
				let time = 60;
				const interval = setInterval(() => {
					if (time > 0) {
						codetext = `${time}秒后重试`;
						time--;
					} else {
						codetext = '发送验证码';
						isCounting = false;
						clearInterval(interval);
					}
				}, 1000);
			} else {
				toast.error(`验证码发送失败，请稍后再试。`);
			}
		} catch (error) {
			toast.error(`验证码发送失败: ${error}`);
		}
	}


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
					// 处理关注成功，进行登录
					try {
						const sessionUser = await weChatFollowLogin(response.openid, wechatSceneId);
						await setSessionUser(sessionUser);
					} catch (loginError) {
						console.error('微信登录失败:', loginError);
						toast.error(`微信登录失败: ${loginError}`);
						// 登录失败后重新获取二维码
						setTimeout(() => {
							getWeChatQR();
						}, 1000);
					}
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

	// 刷新微信二维码
	const refreshWeChatQR = () => {
		stopWeChatPolling();
		getWeChatQR();
	};

	// 当切换到微信登录时获取二维码
	$: if (login === 'wechat' && mode === 'signin') {
		getWeChatQR();
	}

	// 当切换到其他登录方式时停止微信轮询
	$: if (login !== 'wechat') {
		stopWeChatPolling();
	}

	onMount(async () => {
		if ($user !== undefined) {
			const redirectPath = querystringValue('redirect') || '/';
			goto(redirectPath);
		}
		await checkOauthCallback();

		loaded = true;
		setLogoImage();

		if (($config?.features.auth_trusted_header ?? false) || $config?.features.auth === false) {
			await signInHandler();
		} else {
			onboarding = $config?.onboarding ?? false;
		}
	});

	// 绑定手机号相关函数
	const handleBindPhone = async () => {
		if (!phone || !phonecode) {
			toast.error('请填写手机号和验证码');
			return;
		}

		try {
			const token = localStorage.getItem('token');
			await bindPhoneNumber(phone, phonecode, token);
			toast.success('手机号绑定成功！');
			showBindPhoneModal = false;
			needBindPhone = false;
			
			// 绑定成功后跳转
			const redirectPath = querystringValue('redirect') || '/';
			goto(redirectPath);
		} catch (error) {
			console.error('绑定手机号失败:', error);
			toast.error(`绑定失败: ${error}`);
		}
	};

	const skipBindPhone = () => {
		showBindPhoneModal = false;
		needBindPhone = false;
		const redirectPath = querystringValue('redirect') || '/';
		goto(redirectPath);
	};

	// 组件销毁时清理轮询
	onDestroy(() => {
		stopWeChatPolling();
	});
</script>

<svelte:head>
	<title>
		{`${$WEBUI_NAME}`}
	</title>
</svelte:head>

<OnBoarding
	bind:show={onboarding}
	getStartedHandler={() => {
		onboarding = false;
		mode = $config?.features.enable_ldap ? 'ldap' : 'signup';
	}}
/>

<div class="w-full h-screen max-h-[100dvh] text-white relative">
	<div class="w-full h-full absolute top-0 left-0 bg-white dark:bg-black"></div>

	<div class="w-full absolute top-0 left-0 right-0 h-8 drag-region" />

	{#if loaded}
		<div class="fixed m-10 z-50">
			<div class="flex space-x-2">
				<div class=" self-center">
					<img
						id="logo"
						crossorigin="anonymous"
						src="{WEBUI_BASE_URL}/static/splash.png"
						class=" w-20 rounded-full"
						alt=""
					/>
				</div>
			</div>
		</div>

		<div
			class="fixed bg-transparent min-h-screen w-full flex justify-center font-primary z-50 text-black dark:text-white"
		>
			<div class="w-full sm:max-w-md px-10 min-h-screen flex flex-col text-center">
				{#if ($config?.features.auth_trusted_header ?? false) || $config?.features.auth === false}
					<div class=" my-auto pb-10 w-full">
						<div
							class="flex items-center justify-center gap-3 text-xl sm:text-2xl text-center font-semibold dark:text-gray-200"
						>
							<div>
								{$i18n.t('Signing in to {{WEBUI_NAME}}', { WEBUI_NAME: $WEBUI_NAME })}
							</div>

							<div>
								<Spinner />
							</div>
						</div>
					</div>
				{:else}
					<div class="  my-auto pb-10 w-full dark:text-gray-100">
						<div class="mb-1">
							<div class=" text-2xl font-medium">
								{#if $config?.onboarding ?? false}
									{$i18n.t(`Get started with {{WEBUI_NAME}}`, { WEBUI_NAME: $WEBUI_NAME })}
								{:else if mode === 'ldap'}
									{$i18n.t(`Sign in to {{WEBUI_NAME}} with LDAP`, { WEBUI_NAME: $WEBUI_NAME })}
								{:else if mode === 'signin'}
									{$i18n.t(`Sign in to {{WEBUI_NAME}}`, { WEBUI_NAME: $WEBUI_NAME })}
								{:else}
									{$i18n.t(`Sign up to {{WEBUI_NAME}}`, { WEBUI_NAME: $WEBUI_NAME })}
								{/if}
							</div>

							{#if $config?.onboarding ?? false}
								<div class="mt-1 text-xs font-medium text-gray-600 dark:text-gray-500">
									ⓘ {$WEBUI_NAME}
									{$i18n.t(
										'does not make any external connections, and your data stays securely on your locally hosted server.'
									)}
								</div>
							{/if}
						</div>
						<!-- {#if mode === 'signin'} -->
						<div class=" flex w-full">
							<div
								class="flex gap-1 scrollbar-none w-fit text-center text-base font-medium rounded-full bg-transparent pt-1"
							>
								<button
									on:click={() => (login = 'email')}
									class="min-w-fit rounded-full p-1.5 pl-0 pb-0 {login == 'email'
										? ''
										: 'text-gray-300 dark:text-gray-600 hover:text-gray-700 dark:hover:text-white'} transition"
								>
									{mode === 'signin' ? $i18n.t('Email login') : '邮箱注册'}
								</button>
								<button
									on:click={() => (login = 'phone')}
									class="min-w-fit rounded-full p-1.5 pb-0 {login == 'phone'
										? ''
										: 'text-gray-300 dark:text-gray-600 hover:text-gray-700 dark:hover:text-white'} transition"
									>{mode === 'signin' ? $i18n.t('Phone login') : '手机号注册'}</button
								>
								{#if mode === 'signin'}
									<button
										on:click={() => (login = 'wechat')}
										class="min-w-fit rounded-full p-1.5 pb-0 {login == 'wechat'
											? ''
											: 'text-gray-300 dark:text-gray-600 hover:text-gray-700 dark:hover:text-white'} transition"
										>{$i18n.t('Wechat login')}</button
									>
									{/if}
							</div>
						</div>

						<form
							class=" flex flex-col justify-center"
							on:submit={(e) => {
								e.preventDefault();
								submitHandler();
							}}
						>
							{#if $config?.features.enable_login_form || $config?.features.enable_ldap}
								{#if login === 'email'}
									<div class="flex flex-col mt-4">
										{#if mode === 'signup'}
											<div class="mb-2">
												<label for="name" class="text-sm font-medium text-left mb-1 block"
													>{$i18n.t('Name')}</label
												>
												<input
													bind:value={name}
													type="text"
													id="name"
													class="my-0.5 w-full text-sm outline-hidden bg-transparent"
													autocomplete="name"
													placeholder={$i18n.t('Enter Your Full Name')}
													required
												/>
											</div>
										{/if}

										{#if mode === 'ldap'}
											<div class="mb-2">
												<label for="username" class="text-sm font-medium text-left mb-1 block"
													>{$i18n.t('Username')}</label
												>
												<input
													bind:value={ldapUsername}
													type="text"
													class="my-0.5 w-full text-sm outline-hidden bg-transparent"
													autocomplete="username"
													name="username"
													id="username"
													placeholder={$i18n.t('Enter Your Username')}
													required
												/>
											</div>
										{:else}
											<div class="mb-2">
												<label for="email" class="text-sm font-medium text-left mb-1 block"
													>{$i18n.t('Email')}</label
												>
												<input
													bind:value={email}
													type="email"
													id="email"
													class="my-0.5 w-full text-sm outline-hidden bg-transparent"
													autocomplete="email"
													name="email"
													placeholder={$i18n.t('Enter Your Email')}
													required
												/>
											</div>
										{/if}

										<div>
											<label for="password" class="text-sm font-medium text-left mb-1 block"
												>{$i18n.t('Password')}</label
											>
											<input
												bind:value={password}
												type="password"
												id="password"
												class="my-0.5 w-full text-sm outline-hidden bg-transparent"
												placeholder={$i18n.t('Enter Your Password')}
												autocomplete="current-password"
												name="current-password"
												required
											/>
										</div>
									</div>
								{:else if login === 'phone'}
									<div class="flex flex-col mt-4">
										{#if mode === 'signup'}
											<div class="mb-2">
												<label for="name" class="text-sm font-medium text-left mb-1 block"
													>{$i18n.t('Name')}</label
												>
												<input
													bind:value={name}
													type="text"
													id="name"
													class="my-0.5 w-full text-sm outline-hidden bg-transparent"
													autocomplete="name"
													placeholder={$i18n.t('Enter Your Full Name')}
													required
												/>
											</div>

											<div>
												<label for="password" class="text-sm font-medium text-left mb-1 block"
													>{$i18n.t('Password')}</label
												>
												<input
													bind:value={password}
													type="password"
													id="password"
													class="my-0.5 w-full text-sm outline-hidden bg-transparent"
													placeholder={$i18n.t('Enter Your Password')}
													autocomplete="current-password"
													name="current-password"
													required
												/>
											</div>
										{/if}
										<div class="mb-2">
											<label for="name" class="text-sm font-medium text-left mb-1 block"
												>{$i18n.t('Phone')}</label
											>
											<input
												bind:value={phone}
												type="text"
												id="name"
												class="my-0.5 w-full text-sm outline-hidden bg-transparent"
												autocomplete="name"
												placeholder="请输入您的手机号"
												required
											/>
										</div>
										<div class="mb-2">
											<label for="username" class="text-sm font-medium text-left mb-1 block"
												>{$i18n.t('Phone Code')}</label
											>
											<div class="flex gap-1">
												<input
													bind:value={phonecode}
													type="text"
													class="my-0.5 flex-2 w-full text-sm outline-hidden bg-transparent"
													autocomplete="username"
													name="username"
													id="username"
													placeholder="请输入验证码"
													required
												/>
												<button
													on:click={sendCode}
													class="bg-gray-700/5 flex-1 hover:bg-gray-700/10 dark:bg-gray-100/5 dark:hover:bg-gray-100/10 dark:text-gray-300 dark:hover:text-white transition w-full rounded-full font-medium text-sm py-2.5"
													type="button"
													disabled={isCounting}
												>
													{codetext}
												</button>
											</div>
										</div>
									</div>
									{:else if login === 'wechat'}
									<div class="flex flex-col mt-4 items-center">
										{#if wechatQRCode && !qrCodeExpired}
											<div class="bg-white p-1 rounded-lg shadow-md border-1 border-gray-200 dark:border-gray-600">
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
												<div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 mb-4">
													<div class="text-red-600 dark:text-red-400 text-sm font-medium">
														⚠️ 二维码已过期
													</div>
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
												<div class="bg-gray-100 dark:bg-gray-800 rounded-lg p-8 mb-4 w-48 h-48 flex items-center justify-center">
													<div class="text-center">
														<Spinner class="w-8 h-8 mx-auto mb-2" />
														<div class="text-sm text-gray-600 dark:text-gray-400">
															正在生成二维码...
														</div>
													</div>
												</div>
											</div>
										{/if}
										
										<div class="mt-4 text-xs text-gray-500 dark:text-gray-400 text-center max-w-xs leading-relaxed">
											💡 请使用微信扫描上方二维码关注公众号，关注成功后即可自动登录
										</div>
										
										{#if wechatPolling}
											<div class="mt-2 text-xs text-blue-600 dark:text-blue-400 text-center">
												二维码有效期：10分钟
											</div>
										{/if}
									</div>
								{/if}
							{/if}
							<div class="mt-5">
								{#if $config?.features.enable_login_form || $config?.features.enable_ldap}
									{#if mode === 'ldap'}
										<button
											class="bg-gray-700/5 hover:bg-gray-700/10 dark:bg-gray-100/5 dark:hover:bg-gray-100/10 dark:text-gray-300 dark:hover:text-white transition w-full rounded-full font-medium text-sm py-2.5"
											type="submit"
										>
											{$i18n.t('Authenticate')}
										</button>
									{:else}
										{#if login !== 'wechat'}
											<button
												class="bg-gray-700/5 hover:bg-gray-700/10 dark:bg-gray-100/5 dark:hover:bg-gray-100/10 dark:text-gray-300 dark:hover:text-white transition w-full rounded-full font-medium text-sm py-2.5"
												type="submit"
											>
												{mode === 'signin'
													? $i18n.t('Sign in')
													: ($config?.onboarding ?? false)
														? $i18n.t('Create Admin Account')
														: $i18n.t('Create Account')}
											</button>
										{/if}
										{#if $config?.features.enable_signup && !($config?.onboarding ?? false)}
											<div class=" mt-4 text-sm text-center">
												{#if login == 'email'}
													{mode === 'signin'
														? $i18n.t("Don't have an account?")
														: $i18n.t('Already have an account?')}
												{:else if login != 'email'}
													{login === 'phone'
														? mode === 'signin'
															? '手机号获取验证码进行登录。没有账号？'
															: '已经拥有账号了？'
														: '已经拥有账号了？'}
												{/if}

												<button
													class=" font-medium underline"
													type="button"
													on:click={() => {
														if (mode === 'signin') {
															mode = 'signup';
															login = 'email'
														} else {
															mode = 'signin';
														}
													}}
												>
													{mode === 'signin' ? $i18n.t('Sign up') : $i18n.t('Sign in')}
												</button>
											</div>
										{/if}
									{/if}
								{/if}
							</div>
						</form>

						{#if Object.keys($config?.oauth?.providers ?? {}).length > 0}
							<div class="inline-flex items-center justify-center w-full">
								<hr class="w-32 h-px my-4 border-0 dark:bg-gray-100/10 bg-gray-700/10" />
								{#if $config?.features.enable_login_form || $config?.features.enable_ldap}
									<span
										class="px-3 text-sm font-medium text-gray-900 dark:text-white bg-transparent"
										>{$i18n.t('or')}</span
									>
								{/if}

								<hr class="w-32 h-px my-4 border-0 dark:bg-gray-100/10 bg-gray-700/10" />
							</div>
							<div class="flex flex-col space-y-2">
								{#if $config?.oauth?.providers?.google}
									<button
										class="flex justify-center items-center bg-gray-700/5 hover:bg-gray-700/10 dark:bg-gray-100/5 dark:hover:bg-gray-100/10 dark:text-gray-300 dark:hover:text-white transition w-full rounded-full font-medium text-sm py-2.5"
										on:click={() => {
											window.location.href = `${WEBUI_BASE_URL}/oauth/google/login`;
										}}
									>
										<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" class="size-6 mr-3">
											<path
												fill="#EA4335"
												d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"
											/><path
												fill="#4285F4"
												d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"
											/><path
												fill="#FBBC05"
												d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"
											/><path
												fill="#34A853"
												d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"
											/><path fill="none" d="M0 0h48v48H0z" />
										</svg>
										<span>{$i18n.t('Continue with {{provider}}', { provider: 'Google' })}</span>
									</button>
								{/if}
								{#if $config?.oauth?.providers?.microsoft}
									<button
										class="flex justify-center items-center bg-gray-700/5 hover:bg-gray-700/10 dark:bg-gray-100/5 dark:hover:bg-gray-100/10 dark:text-gray-300 dark:hover:text-white transition w-full rounded-full font-medium text-sm py-2.5"
										on:click={() => {
											window.location.href = `${WEBUI_BASE_URL}/oauth/microsoft/login`;
										}}
									>
										<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 21 21" class="size-6 mr-3">
											<rect x="1" y="1" width="9" height="9" fill="#f25022" /><rect
												x="1"
												y="11"
												width="9"
												height="9"
												fill="#00a4ef"
											/><rect x="11" y="1" width="9" height="9" fill="#7fba00" /><rect
												x="11"
												y="11"
												width="9"
												height="9"
												fill="#ffb900"
											/>
										</svg>
										<span>{$i18n.t('Continue with {{provider}}', { provider: 'Microsoft' })}</span>
									</button>
								{/if}
								{#if $config?.oauth?.providers?.github}
									<button
										class="flex justify-center items-center bg-gray-700/5 hover:bg-gray-700/10 dark:bg-gray-100/5 dark:hover:bg-gray-100/10 dark:text-gray-300 dark:hover:text-white transition w-full rounded-full font-medium text-sm py-2.5"
										on:click={() => {
											window.location.href = `${WEBUI_BASE_URL}/oauth/github/login`;
										}}
									>
										<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" class="size-6 mr-3">
											<path
												fill="currentColor"
												d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.92 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57C20.565 21.795 24 17.31 24 12c0-6.63-5.37-12-12-12z"
											/>
										</svg>
										<span>{$i18n.t('Continue with {{provider}}', { provider: 'GitHub' })}</span>
									</button>
								{/if}
								{#if $config?.oauth?.providers?.oidc}
									<button
										class="flex justify-center items-center bg-gray-700/5 hover:bg-gray-700/10 dark:bg-gray-100/5 dark:hover:bg-gray-100/10 dark:text-gray-300 dark:hover:text-white transition w-full rounded-full font-medium text-sm py-2.5"
										on:click={() => {
											window.location.href = `${WEBUI_BASE_URL}/oauth/oidc/login`;
										}}
									>
										<svg
											xmlns="http://www.w3.org/2000/svg"
											fill="none"
											viewBox="0 0 24 24"
											stroke-width="1.5"
											stroke="currentColor"
											class="size-6 mr-3"
										>
											<path
												stroke-linecap="round"
												stroke-linejoin="round"
												d="M15.75 5.25a3 3 0 0 1 3 3m3 0a6 6 0 0 1-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1 1 21.75 8.25Z"
											/>
										</svg>

										<span
											>{$i18n.t('Continue with {{provider}}', {
												provider: $config?.oauth?.providers?.oidc ?? 'SSO'
											})}</span
										>
									</button>
								{/if}
							</div>
						{/if}

						{#if $config?.features.enable_ldap && $config?.features.enable_login_form}
							<div class="mt-2">
								<button
									class="flex justify-center items-center text-xs w-full text-center underline"
									type="button"
									on:click={() => {
										if (mode === 'ldap')
											mode = ($config?.onboarding ?? false) ? 'signup' : 'signin';
										else mode = 'ldap';
									}}
								>
									<span
										>{mode === 'ldap'
											? $i18n.t('Continue with Email')
											: $i18n.t('Continue with LDAP')}</span
									>
								</button>
							</div>
						{/if}
					</div>
				{/if}
			</div>
		</div>
	{/if}
</div>

<!-- 绑定手机号弹窗 -->
{#if showBindPhoneModal}
	<div class="fixed inset-0 z-[9999] flex items-center justify-center bg-black bg-opacity-50">
		<div class="bg-white dark:bg-gray-800 rounded-lg p-6 w-full max-w-md mx-4 shadow-2xl">
			<div class="text-center mb-6">
				<h2 class="text-xl font-semibold text-gray-900 dark:text-white mb-2">
					完善账户信息
				</h2>
				<p class="text-sm text-gray-600 dark:text-gray-400">
					为了账户安全，请绑定您的手机号
				</p>
			</div>

			<div class="space-y-4">
				<div>
					<label for="bind-phone" class="text-sm font-medium text-left mb-1 block text-gray-700 dark:text-gray-300">
						手机号
					</label>
					<input
						bind:value={phone}
						type="text"
						id="bind-phone"
						class="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
						placeholder="请输入您的手机号"
						required
					/>
				</div>

				<div>
					<label for="bind-code" class="text-sm font-medium text-left mb-1 block text-gray-700 dark:text-gray-300">
						验证码
					</label>
					<div class="flex gap-2">
						<input
							bind:value={phonecode}
							type="text"
							id="bind-code"
							class="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 dark:bg-gray-700 dark:text-white"
							placeholder="请输入验证码"
							required
						/>
						<button
							on:click={sendCode}
							class="px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg font-medium text-sm transition disabled:opacity-50"
							type="button"
							disabled={isCounting}
						>
							{codetext}
						</button>
					</div>
				</div>
			</div>

			<div class="flex gap-3 mt-6">
				<button
					on:click={skipBindPhone}
					class="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg font-medium text-sm transition hover:bg-gray-50 dark:hover:bg-gray-700"
				>
					暂时跳过
				</button>
				<button
					on:click={handleBindPhone}
					class="flex-1 px-4 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg font-medium text-sm transition"
				>
					绑定手机号
				</button>
			</div>
		</div>
	</div>
{/if}
