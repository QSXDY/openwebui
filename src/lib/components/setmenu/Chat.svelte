<script lang="ts">
	import { toast } from 'svelte-sonner';
	import { goto } from '$app/navigation';
	import { onMount, getContext } from 'svelte';
	import { user } from '$lib/stores';
	import ConfirmDialog from '$lib/components/common/ExchangeDialog.svelte';
	import AdminDialog from '$lib/components/common/AdminDialog.svelte';
	import PaymentDialog from '$lib/components/common/PaymentDialog.svelte';
	import { getUsers, usersubscriptionmenu, subscriptionprocess } from '$lib/apis/setmenu';

	const i18n = getContext('i18n');

	let showDeleteConfirmDialog = false;
	let showAdminDialog = false;
	let showPaymentDialog = false;
	let loaded = false;
	let untype = '个人';
	let suntype = '个1人';
	let menus: any[] = [];
	let frmoMenu = null;

	const usermenu = async () => {
		try {
			const res = await usersubscriptionmenu(localStorage.token, $user.id).catch((error) => {
				toast.error(`${error}`);
				return null;
			});

			if (res) {
				if (res.subscription.plan == null) {
					return;
				}
				const unmatchedPlans = [res.subscription.plan];
				const processedPlans = unmatchedPlans.map((plan) => ({
					...plan,
					user_plan: 2
				}));
				const menusPlans = menus.map((plan) => ({
					...plan,
					user_plan: 0
				}));
				// 1. 将当前订购的套餐转换为 Map，便于快速查找
				const processedPlanMap = new Map(
					processedPlans.map((plan) => [plan.id, { ...plan, user_plan: 1 }])
				);

				// 2. 处理套餐列表：匹配的套餐标记为已订购，未匹配的保持原样
				const matchedMenus = menusPlans.map((menu) => {
					if (processedPlanMap.has(menu.id)) {
						// 如果套餐列表中的套餐存在于当前订购中，标记为已订购
						const matchedPlan = processedPlanMap.get(menu.id);
						processedPlanMap.delete(menu.id); // 删除已匹配的，剩余的是需要新增的
						return { ...menu, ...matchedPlan, user_plan: 1 };
					}
					return menu; // 未匹配的保持原样
				});

				// 3. 将未在套餐列表中出现的当前订购套餐添加到列表首位
				const newMenus = [
					...Array.from(processedPlanMap.values()), // 新增的套餐（未在原列表中）
					...matchedMenus // 处理后的原套餐列表
				];
				menus = newMenus;
				console.log('套餐套餐我的', newMenus);
			}
		} catch (err) {
			console.error(err);
		}
	};

	const menuList = async () => {
		try {
			const res = await getUsers(localStorage.token).catch((error) => {
				toast.error(`${error}`);
				return null;
			});

			if (res) {
				menus = res.plans ?? [];
				usermenu();
			}
		} catch (err) {
			console.error(err);
		}
	};

	onMount(async () => {
		console.log('用户', $user);
		untype = '个人';
		loaded = true;
		menuList();
	});

	const nihasd = async () => {
		try {
			const res = await subscriptionprocess(localStorage.token).catch((error) => {
				toast.error(`${error}`);
				return null;
			});

			if (res) {
				console.log('订单', res);
			}
		} catch (err) {
			console.error(err);
		}
	};
	import { showSidebar } from '$lib/stores';
	import MenuLines from '$lib/components/icons/MenuLines.svelte';
</script>

<ConfirmDialog bind:show={showDeleteConfirmDialog} menu={frmoMenu} on:confirm={() => {}} />
<AdminDialog bind:show={showAdminDialog} on:confirm={() => {}} />
<PaymentDialog
	bind:show={showPaymentDialog}
	on:confirm={() => {
		menuList();
		showPaymentDialog = false;
	}}
/>
<div class="flex flex-col items-center w-full min-h-screen bg-white p-3 md:p-8">
	<div class="{$showSidebar ? 'md:hidden' : ''} self-center w-full flex flex-none items-center">
		<button
			id="sidebar-toggle-button"
			class="cursor-pointer p-1.5 flex rounded-xl hover:bg-gray-100 dark:hover:bg-gray-850 transition"
			on:click={() => {
				showSidebar.set(!$showSidebar);
			}}
			aria-label="Toggle Sidebar"
		>
			<div class=" m-auto self-center">
				<MenuLines />
			</div>
		</button>
	</div>
	<!-- 顶部标题和切换 -->
	<div class="text-center mb-6 flex flex-col items-center">
		<div class="text-4xl font-extrabold mb-2 text-black">{$i18n.t('Upgrade Package')}</div>
		<div class="text-base text-gray-500 mb-3">
			{$i18n.t('Get more points to improve efficiency')}
		</div>
		<div class="flex justify-center gap-4 mb-4">
			<button
				type="button"
				class="text-blue-600 cursor-pointer text-sm hover:underline bg-transparent border-none p-0"
				on:click={() => {
					showPaymentDialog = true;
				}}
			>
				<span class="flex items-center gap-1">
					<svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" viewBox="0 0 24 24"
						><g
							fill="none"
							stroke="currentColor"
							stroke-linecap="round"
							stroke-linejoin="round"
							stroke-width="1.5"
							><ellipse cx="15.5" cy="11" rx="6.5" ry="2" /><path
								d="M22 15.5c0 1.105-2.91 2-6.5 2s-6.5-.895-6.5-2"
							/><path d="M22 11v8.8c0 1.215-2.91 2.2-6.5 2.2S9 21.015 9 19.8V11" /><ellipse
								cx="8.5"
								cy="4"
								rx="6.5"
								ry="2"
							/><path d="M6 11c-1.892-.23-3.63-.825-4-2m4 7c-1.892-.23-3.63-.825-4-2" /><path
								d="M6 21c-1.892-.23-3.63-.826-4-2V4m13 2V4"
							/></g
						></svg
					>
					{$i18n.t('exchangecode-title')}
				</span>
			</button>
			<button
				type="button"
				class="text-blue-600 cursor-pointer text-sm hover:underline bg-transparent border-none p-0"
				on:click={() => {
					menuList();
				}}
			>
				<span class="flex items-center gap-1">
					<svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" viewBox="0 0 24 24"
						><path
							fill="currentColor"
							d="M12 20q-3.35 0-5.675-2.325T4 12t2.325-5.675T12 4q1.725 0 3.3.712T18 6.75V5q0-.425.288-.712T19 4t.713.288T20 5v5q0 .425-.288.713T19 11h-5q-.425 0-.712-.288T13 10t.288-.712T14 9h3.2q-.8-1.4-2.187-2.2T12 6Q9.5 6 7.75 7.75T6 12t1.75 4.25T12 18q1.7 0 3.113-.862t2.187-2.313q.2-.35.563-.487t.737-.013q.4.125.575.525t-.025.75q-1.025 2-2.925 3.2T12 20"
						/></svg
					>

					{$i18n.t('refresh-menu-info')}
				</span>
			</button>
		</div>
		{#if suntype === '个人'}
			<div
				class="flex justify-center mb-2 p-1 w-[150px] rounded-full order border-gray-200 bg-gray-100 text-gray-500"
			>
				{#if untype === '个人'}
					<button
						on:click={() => {
							untype = '个人';
						}}
						class="px-2 flex-1 py-1.5 rounded-full border border-gray-200 bg-white text-black font-medium shadow-sm focus:outline-none"
						>{$i18n.t('Personal')}</button
					>
				{:else}
					<button
						on:click={() => {
							untype = '个人';
						}}
						class="px-2 flex-1 py-1.5 rounded-full text-gray-500 font-medium"
						>{$i18n.t('Enterprise')}</button
					>
				{/if}
				{#if untype === '企业'}
					<button
						on:click={() => {
							untype = '企业';
						}}
						class="px-2 flex-1 py-1.5 rounded-full border border-gray-200 bg-white text-black font-medium shadow-sm focus:outline-none"
						>{$i18n.t('Personal')}</button
					>
				{:else}
					<button
						on:click={() => {
							untype = '企业';
						}}
						class="px-2 flex-1 py-1.5 rounded-full text-gray-500 font-medium"
						>{$i18n.t('Enterprise')}</button
					>
				{/if}
			</div>
		{/if}

		<div class="text-xs text-gray-400 mt-2">
			* {$i18n.t('Use two fingers to slide left and right or hold Shift to scroll more')} *
		</div>
	</div>

	{#if untype === '个人'}
		<!-- 套餐卡片 -->
		<div class="max-w-6xl w-full overflow-auto mx-auto">
			<div class="flex">
				<!-- 修复：移除重复的class属性，修正CSS类名 -->
				<div class=" flex gap-4 pb-5 px-1 md:justify-center">
					{#each menus.filter((menu) => menu.is_active) as menu (menu.id)}
						<div class="flex-shrink-0 w-[280px] snap-center svelte-du15c4">
							<div
								class=" bg-white flex-1 min-w-[260px] max-w-[280px] items-start border border-gray-200 shadow-md
							 dark:border-gray-800 rounded-xl p-6 h-full flex flex-col relative hover:shadow-lg transition-all duration-300"
							>
								<div class="w-full">
									{#if menu.user_plan > 0}
										<div
											class={menu.user_plan === 1
												? 'absolute top-4 right-4 text-xs px-3 py-0.5 rounded-full text-white bg-green-500'
												: 'absolute top-4 right-4 text-xs px-3 py-0.5 rounded-full text-white bg-[#155DFC]'}
										>
											当前套餐
										</div>
									{/if}

									<div class="text-xl font-bold mb-2 text-black">{menu.name}</div>
									<div class="text-3xl font-extrabold mb-1 text-black">
										¥ {menu.price}
										<span class="text-base font-normal text-gray-500">/ {menu.duration}天</span>
									</div>
									<div class="text-xl font-bold mb-2 text-black">
										{menu.credits * menu.duration}V豆<span
											class="text-base font-normal text-gray-500"
										></span>
									</div>

									<div class="text-gray-500 text-sm mb-4 max-h-[280px] overflow-auto">
										{menu.description}
									</div>
								</div>
								<div class="flex-1 w-full flex flex-col justify-end">
									{#if menu.user_plan === 1}
										<div class="text-xs text-gray-400 mb-2">当前使用中</div>
										<button
											class="w-full h-10 bg-green-500 text-white py-2 rounded font-bold flex items-center justify-center gap-2"
											on:click={() => {
												console.log('续费', menu);
												frmoMenu = menu; // 修正：将frmoMenu改为fromMenu
												showDeleteConfirmDialog = true;
											}}
										>
											<span class="mr-1">
												<svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" viewBox="0 0 24 24"
													><g
														fill="none"
														stroke="currentColor"
														stroke-linecap="round"
														stroke-linejoin="round"
														stroke-width="1.5"
														><path
															d="M9.143 3.004L14.857 3m-5.714.004L2 15.004m7.143-12l4.902 9.496m.812-9.5L5.575 21m9.282-18l5.356 9M5.575 21L2 15.004M5.575 21h6.429M2 15.004h10.5m10.166 2.663C22.048 16.097 20.634 15 18.99 15c-1.758 0-3.252 1.255-3.793 3"
														/><path
															d="M20.995 17.772H22.4a.6.6 0 0 0 .6-.6V15.55m-7.666 4.783C15.952 21.903 17.366 23 19.01 23c1.758 0 3.252-1.255 3.793-3"
														/><path d="M17.005 20.228H15.6a.6.6 0 0 0-.6.6v1.622" /></g
													></svg
												>
											</span> 续费
										</button>
									{:else if menu.user_plan === 2}
										<div class="text-xs text-[#155DFC] mb-2">当前使用中</div>
										<button
											class="w-full h-10 bg-[#155DFC] text-white py-2 rounded font-bold flex items-center justify-center gap-2"
											on:click={() => {
												console.log('联系管理员续费', menu);

												showAdminDialog = true; // 添加：触发确认对话框
											}}
										>
											<span class="mr-1"
												><svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" viewBox="0 0 24 24"
													><path
														fill="none"
														stroke="currentColor"
														stroke-linecap="round"
														stroke-linejoin="round"
														stroke-width="1.5"
														d="M9.143 3.004L14.857 3m-5.714.004L2 15.004m7.143-12l4.902 9.496m.812-9.5L5.575 21m9.282-18L21.5 14M5.575 21L2 15.004M5.575 21h6.429M2 15.004h10.5M15 19l3 3l5-5"
													/></svg
												></span
											> 联系管理员续费
										</button>
									{:else}
										<button
											class="w-full h-10 bg-[#333333] text-white py-2 rounded font-bold flex items-center justify-center gap-2"
											on:click={() => {
												console.log('购买', menu);
												frmoMenu = menu; // 修正：将frmoMenu改为fromMenu
												showDeleteConfirmDialog = true;
											}}
										>
											<span class="mr-1"
												><svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" viewBox="0 0 24 24"
													><path
														fill="none"
														stroke="currentColor"
														stroke-linecap="round"
														stroke-linejoin="round"
														stroke-width="1.5"
														d="M9.143 3.004L14.857 3m-5.714.004L2 15.004m7.143-12L18.433 21M14.856 3L22 15.004M14.857 3L5.575 21m12.857 0H5.575m12.857 0L22 15.004M5.575 21L2 15.004m20 0H2"
													/></svg
												></span
											> 购买
										</button>
									{/if}
								</div>
							</div>
						</div>
					{/each}
				</div>
			</div>
		</div>
	{:else}
		<div class=" mt-2 flex flex-col items-center">
			<div class="text-2xl font-bold mb-2 text-black">企业版套餐</div>
			<div class="text-sm text-gray-500 mb-4">
				如需企业版专属套餐、定制功能或批是采购，请联系我们的销售团队。
			</div>
			<button
				class="w-[130px] h-10 bg-[#333333] text-white py-2 rounded font-bold flex items-center justify-center gap-2"
				on:click={() => {
					showAdminDialog = true;
				}}
			>
				<span class="mr-1"> 管理员 </span></button
			>
		</div>
	{/if}
</div>
