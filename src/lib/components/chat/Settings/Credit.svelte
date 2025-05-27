<script lang="ts">
	import { getContext, onMount } from 'svelte';
	import { user } from '$lib/stores';
	import { createTradeTicket, getCreditConfig, listCreditLog } from '$lib/apis/credit';
	import { toast } from 'svelte-sonner';
	import { getSessionUser, getAdminUser } from '$lib/apis/auths';

	const i18n = getContext('i18n');

	type Model = {
		id: string;
		name: string;
	};
	type APIParams = {
		model: Model;
	};
	type Usage = {
		total_price: number;
		prompt_unit_price: number;
		completion_unit_price: number;
		request_unit_price: number;
		completion_tokens: number;
		prompt_tokens: number;
	};
	type LogDetail = {
		desc: string;
		api_params: APIParams;
		usage: Usage;
	};
	type Log = {
		id: string;
		credit: string;
		detail: LogDetail;
		created_at: number;
	};
	let page = 1;
	let hasMore = true;
	let logs: Array<Log> = [];
	const loadLogs = async (append: boolean) => {
		const data = await listCreditLog(localStorage.token, page).catch((error) => {
			toast.error(`${error}`);
			return null;
		});
		if (data.length === 0) {
			hasMore = false;
		}
		if (append) {
			logs = [...logs, ...data];
		} else {
			logs = data;
		}
	};
	const nextLogs = async () => {
		page++;
		await loadLogs(true);
	};

	let credit = 0;
	let adcredit = 0;
	let payType = 'alipay';
	let payTypes = [
		{
			code: 'alipay',
			title: $i18n.t('Alipay')
		},
		{
			code: 'wxpay',
			title: $i18n.t('WXPay')
		}
	];
	let amount = null;

	let config = {
		CREDIT_EXCHANGE_RATIO: 0,
		EZFP_PAY_PRIORITY: 'qrcode'
	};

	let tradeInfo = {
		detail: {
			code: -1,
			msg: '',
			payurl: '',
			qrcode: '',
			urlscheme: '',
			img: '',
			imgDisplayUrl: ''
		}
	};

	const showQRCode = (detail: object): Boolean => {
		if (detail?.img) {
			tradeInfo.detail.imgDisplayUrl = detail.img;
			return true;
		}

		if (detail?.qrcode) {
			document.getElementById('trade-qrcode').innerHTML = '';
			new QRCode(document.getElementById('trade-qrcode'), {
				text: detail.qrcode,
				width: 128,
				height: 128,
				colorDark: '#000000',
				colorLight: '#ffffff',
				correctLevel: QRCode.CorrectLevel.H
			});
			return true;
		}

		return false;
	};

	const redirectLink = (detail: object): Boolean => {
		if (detail?.payurl) {
			window.location.href = detail.payurl;
			return true;
		}

		if (detail?.urlscheme) {
			window.location.href = detail.urlscheme;
			return true;
		}

		return false;
	};

	const handleAddCreditClick = async () => {
		const res = await createTradeTicket(localStorage.token, payType, amount).catch((error) => {
			toast.error(`${error}`);
			return null;
		});
		if (res) {
			tradeInfo = res;
			if (tradeInfo.detail === undefined) {
				toast.error('init payment failed');
				return;
			}

			const detail = tradeInfo.detail;
			if (detail?.code !== 1) {
				toast.error(tradeInfo?.detail?.msg);
				return;
			}

			if (config.EZFP_PAY_PRIORITY === 'qrcode') {
				if (showQRCode(detail)) {
					return;
				}
				redirectLink(detail);
			} else {
				if (redirectLink(detail)) {
					return;
				}
				showQRCode(detail);
			}
		}
	};

	const handleWeChatClick = async () => {
		payType = 'wxpay';
		await handleAddCreditClick();
	};

	const handleAlipayClick = async () => {
		payType = 'alipay';
		await handleAddCreditClick();
	};

	const formatDate = (t: number): string => {
		return new Date(t * 1000).toLocaleString();
	};

	const formatDesc = (log: Log): string => {
		const usage = log?.detail?.usage ?? {};
		if (usage && Object.keys(usage).length > 0) {
			if (usage.total_price !== undefined && usage.total_price !== null) {
				return `-${Math.round(usage.total_price * 1e6) / 1e6}`;
			}
			if (usage.request_unit_price) {
				return `-${usage.request_unit_price / 1e6}`;
			}
			if (usage.prompt_unit_price || usage.completion_unit_price) {
				return `-${Math.round(usage.prompt_tokens * usage.prompt_unit_price + usage.completion_tokens * usage.completion_unit_price) / 1e6}`;
			}
		}
		return log?.detail?.desc;
	};

	const doInit = async () => {
		const sessionUser = await getSessionUser(localStorage.token).catch((error) => {
			toast.error(`${error}`);
			return null;
		});
		await user.set(sessionUser);

		const res = await getCreditConfig(localStorage.token).catch((error) => {
			toast.error(`${error}`);
			return null;
		});
		if (res) {
			config = res;
		}

		credit = $user?.credit ? $user?.credit : 0;
		tradeInfo = {};
		document.getElementById('trade-qrcode').innerHTML = '';

		await loadLogs(false);
	};

	const doInitadd = async () => {
		const sessionUser = await getAdminUser(localStorage.token).catch((error) => {
			toast.error(`${error}`);
			return null;
		});
		adcredit = sessionUser.admin_credit == null ? null : sessionUser.admin_credit;
		console.log('企业积分', sessionUser);
	};

	onMount(async () => {
		await doInit();
		await doInitadd();
	});
</script>

<div class="flex flex-col h-full justify-between text-sm">
	<div class=" space-y-3 lg:max-h-full">
		<div class="space-y-1">
			<div class="flex">
				<div class="pt-0.5 mr-5">
					<div class="flex flex-col w-full">
						<div class="mb-1 text-base font-medium">个人{$i18n.t('Credit')}</div>
						<div class="flex items-center">
							<div>{credit}</div>
							<button class="ml-1" on:click={() => doInit()}>
								<svg
									viewBox="0 0 1024 1024"
									xmlns="http://www.w3.org/2000/svg"
									width="16"
									height="16"
								>
									<path
										d="M832 512a32 32 0 0 0-32 32c0 158.784-129.216 288-288 288s-288-129.216-288-288 129.216-288 288-288c66.208 0 129.536 22.752 180.608 64H608a32 32 0 0 0 0 64h160a32 32 0 0 0 32-32V192a32 32 0 0 0-64 0v80.96A350.464 350.464 0 0 0 512 192C317.92 192 160 349.92 160 544s157.92 352 352 352 352-157.92 352-352a32 32 0 0 0-32-32"
										fill="#3E3A39"
									></path>
								</svg>
							</button>
						</div>
					</div>
				</div>
				{#if adcredit !== null}
					<!-- 使用Svelte规范的{#if}语法，全等判断 -->
					<div class="pt-0.5">
						<div class="flex flex-col w-full">
							<div class="mb-1 text-base font-medium">
								企业{$i18n.t('Credit')}
								<!-- 保留原有i18n翻译 -->
							</div>
							<div class="flex items-center">
								<div>{adcredit}</div>
								<button class="ml-1" on:click={doInitadd}>
									<svg
										viewBox="0 0 1024 1024"
										xmlns="http://www.w3.org/2000/svg"
										width="16"
										height="16"
									>
										<path
											d="M832 512a32 32 0 0 0-32 32c0 158.784-129.216 288-288 288s-288-129.216-288-288 129.216-288 288-288c66.208 0 129.536 22.752 180.608 64H608a32 32 0 0 0 0 64h160a32 32 0 0 0 32-32V192a32 32 0 0 0-64 0v80.96A350.464 350.464 0 0 0 512 192C317.92 192 160 349.92 160 544s157.92 352 352 352 352-157.92 352-352a32 32 0 0 0-32-32"
											fill="#3E3A39"
										></path>
									</svg>
								</button>
							</div>
						</div>
					</div>
				{/if}
			</div>
			<div class="max-h-[14rem] flex flex-col items-center w-full">
				<div id="trade-qrcode" class="max-h-[128px] max-w-[128px]"></div>
				{#if tradeInfo?.detail?.imgDisplayUrl}
					<img
						src={tradeInfo?.detail?.imgDisplayUrl}
						alt="trade qrcode"
						class="object-contain max-h-[128px] max-w-[128px]"
					/>
				{/if}
				{#if tradeInfo?.detail?.qrcode || tradeInfo?.detail?.imgDisplayUrl}
					<div class="mt-2">
						{$i18n.t('Please refresh after payment')}
					</div>
				{/if}
			</div>

			{#if !tradeInfo?.detail?.qrcode && !tradeInfo?.detail?.imgDisplayUrl}
				<hr class=" border-gray-100 dark:border-gray-700/10 my-2.5 w-full" />

				<div class="pt-0.5">
					<div class="flex flex-col w-full">
						<div class="mb-1 text-base font-medium">{$i18n.t('Credit Log')}</div>
						<div
							class="overflow-y-scroll max-h-[14rem] flex flex-col scrollbar-hidden relative whitespace-nowrap overflow-x-auto max-w-full rounded-sm"
						>
							{#if logs.length > 0}
								<table
									class="w-full text-sm text-left text-gray-500 dark:text-gray-400 table-auto max-w-full rounded-sm}"
								>
									<thead
										class="text-xs text-gray-700 uppercase bg-gray-50 dark:bg-gray-850 dark:text-gray-400 -translate-y-0.5"
									>
										<tr>
											<th scope="col" class="px-3 py-1.5 select-none w-3">
												{$i18n.t('Date')}
											</th>
											<th scope="col" class="px-3 py-1.5 select-none w-3">
												{$i18n.t('Credit')}
											</th>
											<th scope="col" class="px-3 py-1.5 select-none w-3">
												{$i18n.t('Model')}
											</th>
											<th scope="col" class="px-3 py-1.5 select-none w-3">
												{$i18n.t('Desc')}
											</th>
										</tr>
									</thead>
									<tbody>
										{#each logs as log}
											<tr class="bg-white dark:bg-gray-900 dark:border-gray-850 text-xs group">
												<td
													class="px-3 py-1.5 text-left font-medium text-gray-900 dark:text-white w-fit"
												>
													<div class=" line-clamp-1">
														{formatDate(log.created_at)}
													</div>
												</td>
												<td
													class="px-3 py-1.5 text-left font-medium text-gray-900 dark:text-white w-fit"
												>
													<div class=" line-clamp-1">
														{parseFloat(log.credit).toFixed(6)}
													</div>
												</td>
												<td
													class="px-3 py-1.5 text-left font-medium text-gray-900 dark:text-white w-fit"
												>
													<div class=" line-clamp-1">
														{log.detail?.api_params?.model?.name ||
															log.detail?.api_params?.model?.id ||
															'- -'}
													</div>
												</td>
												<td
													class="px-3 py-1.5 text-left font-medium text-gray-900 dark:text-white w-fit"
												>
													<div class=" line-clamp-1">
														{formatDesc(log)}
													</div>
												</td>
											</tr>
										{/each}
									</tbody>
								</table>
								{#if hasMore}
									<button
										class="text-xs mt-2"
										type="button"
										on:click={() => {
											nextLogs(true);
										}}
									>
										{$i18n.t('Load More')}
									</button>
								{/if}
							{:else}
								<div>{$i18n.t('No Log')}</div>
							{/if}
						</div>
					</div>
				</div>
			{/if}
		</div>
	</div>
</div>
